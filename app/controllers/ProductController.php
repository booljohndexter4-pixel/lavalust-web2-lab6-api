<?php
defined('PREVENT_DIRECT_ACCESS') OR exit('No direct script access allowed');

class ProductController extends Controller
{
    public function __construct()
    {
        parent::__construct();
        $this->call->database();
        $this->call->library('api');
        header('Content-Type: application/json; charset=utf-8');
    }

    // GET /api/products  (display products)
    public function index()
    {
        $this->api->require_method('GET');
        $this->api->require_jwt();

        $stmt = $this->db->raw("SELECT * FROM products ORDER BY id DESC");
        $this->api->respond(['data' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    }

    // POST /api/products  (add a product)
    public function store()
    {
        $this->api->require_method('POST');
        $this->require_admin();

        $data = $this->api->body();
        $this->validate_product($data);

        $this->db->raw(
            "INSERT INTO products (product_name, description, price, quantity) VALUES (?, ?, ?, ?)",
            [
                $data['product_name'],
                $data['description'] ?? '',
                $data['price'],
                $data['quantity'],
            ]
        );

        $id = $this->db->raw("SELECT LAST_INSERT_ID() AS id")->fetch(PDO::FETCH_ASSOC)['id'];

        $this->api->respond([
            'message' => 'Product added',
            'data'    => $this->find_product($id),
        ], 201);
    }

    // PUT or PATCH /api/products/{id}  (update a product)
    public function update($id)
    {
        if (!in_array($_SERVER['REQUEST_METHOD'], ['PUT', 'PATCH'], true)) {
            $this->api->respond_error('Method Not Allowed', 405);
        }
        $this->require_admin();

        $current = $this->find_product($id);
        if (!$current) {
            $this->api->respond_error('Product not found', 404);
        }

        // Fields that were not sent keep their old value.
        $data = array_merge($current, $this->api->body());
        $this->validate_product($data);

        $this->db->raw(
            "UPDATE products SET product_name = ?, description = ?, price = ?, quantity = ? WHERE id = ?",
            [
                $data['product_name'],
                $data['description'] ?? '',
                $data['price'],
                $data['quantity'],
                $id,
            ]
        );

        $this->api->respond([
            'message' => 'Product updated',
            'data'    => $this->find_product($id),
        ]);
    }

    // DELETE /api/products/{id}  (delete a product)
    public function destroy($id)
    {
        $this->api->require_method('DELETE');
        $this->require_admin();

        if (!$this->find_product($id)) {
            $this->api->respond_error('Product not found', 404);
        }

        $this->db->raw("DELETE FROM products WHERE id = ?", [$id]);
        $this->api->respond(['message' => 'Product deleted']);
    }

    private function find_product($id)
    {
        $stmt = $this->db->raw("SELECT * FROM products WHERE id = ? LIMIT 1", [$id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function require_admin()
    {
        $auth = $this->api->require_jwt();
        if (($auth['role'] ?? '') !== 'admin') {
            $this->api->respond_error('Admin access required', 403);
        }
    }

    private function validate_product($data)
    {
        if (empty($data['product_name'])) {
            $this->api->respond_error('Product name is required', 422);
        }
        if (!isset($data['price']) || !is_numeric($data['price']) || $data['price'] < 0) {
            $this->api->respond_error('Price must be a number (0 or higher)', 422);
        }
        if (!isset($data['quantity']) || filter_var($data['quantity'], FILTER_VALIDATE_INT) === false || $data['quantity'] < 0) {
            $this->api->respond_error('Quantity must be a whole number (0 or higher)', 422);
        }
    }
}
