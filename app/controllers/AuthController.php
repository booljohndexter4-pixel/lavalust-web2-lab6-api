<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class AuthController extends Controller
{
        public function __construct()
    {
        parent::__construct();
        $this->call->database();
        $this->call->library('api');
        header('Content-Type: application/json; charset=utf-8');
    }

    // POST /api/register
    public function register()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit();

        $data     = $this->api->body();
        $username = $data['username'] ?? '';
        $email    = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        if ($username === '' || $email === '' || $password === '') {
            $this->api->respond_error('Username, email and password are required', 422);
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->api->respond_error('Invalid email address', 422);
        }
        if (strlen($password) < 6) {
            $this->api->respond_error('Password must be at least 6 characters', 422);
        }

        $stmt = $this->db->raw(
            "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
            [$username, $email]
        );
        if ($stmt->fetch(PDO::FETCH_ASSOC)) {
            $this->api->respond_error('Username or email already exists', 409);
        }

        $this->db->raw(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            [$username, $email, password_hash($password, PASSWORD_DEFAULT)]
        );

        $this->api->respond(['message' => 'Registered successfully'], 201);
    }

    // POST /api/login
    public function login()
    {
        $this->api->require_method('POST');
        $this->api->rate_limit();

        $data     = $this->api->body();
        $login    = $data['username'] ?? ($data['email'] ?? '');
        $password = $data['password'] ?? '';

        if ($login === '' || $password === '') {
            $this->api->respond_error('Username and password are required', 422);
        }

        $stmt = $this->db->raw(
            "SELECT id, username, email, password, role, is_active
             FROM users WHERE username = ? OR email = ? LIMIT 1",
            [$login, $login]
        );
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user || !password_verify($password, $user['password'])) {
            $this->api->respond_error('Invalid username or password', 401);
        }
        if (!(int) $user['is_active']) {
            $this->api->respond_error('Account is disabled', 403);
        }

        $tokens = $this->api->issue_tokens([
            'id'   => $user['id'],
            'role' => $user['role'],
        ]);

        $this->api->respond([
            'message' => 'Login successful',
            'user'    => [
                'id'       => $user['id'],
                'username' => $user['username'],
                'email'    => $user['email'],
                'role'     => $user['role'],
            ],
            'tokens'  => $tokens,
        ]);
    }

    // GET /api/me
    public function me()
    {
        $this->api->require_method('GET');
        $auth = $this->api->require_jwt();

        $this->api->respond([
            'id'   => $auth['sub'],
            'role' => $auth['role'],
        ]);
    }

    // POST /api/logout
    public function logout()
    {
        $this->api->require_method('POST');
        $this->api->require_jwt();

        $data = $this->api->body();
        if (!empty($data['refresh_token'])) {
            $this->api->revoke_refresh_token($data['refresh_token']);
        }

        $this->api->respond(['message' => 'Logged out']);
    }
}
