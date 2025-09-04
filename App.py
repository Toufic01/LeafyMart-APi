import traceback
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS
import mysql.connector
import bcrypt
import json
import os
import base64
from datetime import datetime, timedelta
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="leafymart"
    )


# Helper function for image URLs
def absolute_image(db_value: str | None) -> str:
    if not db_value or db_value.lower() == "null":
        return request.host_url.rstrip("/") + "/static/images/default.jpg"

    # Normalize path by removing duplicate slashes
    db_value = db_value.replace("//", "/")

    if db_value.startswith("http"):
        return db_value
    if db_value.startswith("static/"):
        return request.host_url.rstrip("/") + "/" + db_value.lstrip("/")
    if db_value.startswith("/static/"):
        return request.host_url.rstrip("/") + db_value

    # Handle cases where path might be just a filename
    return request.host_url.rstrip("/") + "/static/images/" + db_value.lstrip("/")
# ======================
# AUTHENTICATION ENDPOINTS
# ======================
@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json(force=True)
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        profile_image_base64 = data.get("profile_image")

        if not all([name, email, password, profile_image_base64]):
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        # Decode and save image
        filename = f"profile_{int(datetime.now().timestamp())}.jpg"
        image_folder = os.path.join("static", "images")
        os.makedirs(image_folder, exist_ok=True)
        image_path = os.path.join(image_folder, filename)
        with open(image_path, "wb") as f:
            f.write(base64.b64decode(profile_image_base64))

        # Hash password with bcrypt
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Insert user into database
        db = get_db()
        cursor = db.cursor()

        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "Email already registered"}), 409

        sql = "INSERT INTO users (name, email, password, profile_image) VALUES (%s, %s, %s, %s)"
        cursor.execute(sql, (name, email, hashed_password.decode('utf-8'), filename))
        db.commit()

        cursor.close()
        db.close()

        return jsonify({"success": True, "message": "Registered successfully"})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error: " + str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({
                "message": "Login success",
                "user_id": user["id"],
                "name": user["name"]
            })
        return jsonify({"message": "Invalid email or password"}), 401
    except Exception as e:
        return jsonify({"message": "Login failed", "error": str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route("/profile/<int:user_id>", methods=["GET"])
def profile(user_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT name, email, profile_image FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        user["profile_image_url"] = request.host_url.rstrip("/") + "/static/images/" + user["profile_image"]
        return jsonify({"success": True, "user": user})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/logout", methods=["GET"])
def logout():
    user_id = request.args.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "user_id is required"}), 400

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM cart WHERE user_id = %s", (user_id,))
        db.commit()
        return jsonify({"success": True, "message": f"User {user_id} logged out and cart cleared"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": "Failed to logout", "error": str(e)}), 500
    finally:
        cur.close()
        db.close()



# Verify email exists
@app.route("/verify_email", methods=["POST"])
def verify_email():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "Email required"}), 400

        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, name FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        db.close()

        if user:
            return jsonify({"success": True, "message": "Email found", "name": user["name"]})
        return jsonify({"success": False, "message": "Email not found"}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500

# Update password (hash on server)
@app.route("/update_password", methods=["POST"])
def update_password():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        new_password = data.get("new_password")
        if not email or not new_password:
            return jsonify({"success": False, "message": "Email and new password required"}), 400

        hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if not cur.fetchone():
            cur.close()
            db.close()
            return jsonify({"success": False, "message": "Email not found"}), 404

        cur.execute("UPDATE users SET password = %s, updated_at = %s WHERE email = %s",
                    (hashed, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email))
        db.commit()
        cur.close()
        db.close()
        return jsonify({"success": True, "message": "Password updated"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500



# ======================
# PRODUCT ENDPOINTS
# ======================
@app.route("/products", methods=["GET"])
def get_products():
    category = request.args.get("category")
    search_query = request.args.get("search")

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        if category:
            cur.execute("SELECT * FROM products WHERE category LIKE %s", (f"%{category}%",))
        elif search_query:
            cur.execute("SELECT * FROM products WHERE name LIKE %s", (f"%{search_query}%",))
        else:
            cur.execute("SELECT * FROM products")

        rows = cur.fetchall()
        for row in rows:
            # Add available stock from database (make sure the column exists in your table)
            row['available'] = row.get('available', 0)  # default 0 if missing

            # Clean the image path before processing
            if 'image_url' in row:
                row['image_url'] = row['image_url'].strip() if row['image_url'] else None
                row['image_url'] = absolute_image(row['image_url'])

            # Add fallback if image_url is still empty
            if not row.get('image_url'):
                row['image_url'] = absolute_image(None)

        return jsonify(rows)
    except Exception as e:
        return jsonify({"message": "Failed to get products", "error": str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        cur.execute("""
            SELECT id, name, price, image_url, description, 
                   category, rating, sold
            FROM products
            WHERE id = %s
        """, (product_id,))

        product = cur.fetchone()

        if not product:
            return jsonify({"success": False, "message": "Product not found"}), 404

        # Clean and convert image URL
        if product.get('image_url'):
            product['image_url'] = product['image_url'].strip()
            product['image_url'] = absolute_image(product['image_url'])
        else:
            product['image_url'] = absolute_image(None)

        return jsonify(product), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cur.close()
        db.close()



@app.route("/products/trending", methods=["GET"])
def trending_products():
    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("""
            SELECT *
            FROM products
            ORDER BY sold DESC LIMIT 10
            """)
        rows = cur.fetchall()

        for row in rows:
            row["image_url"] = absolute_image(row.get("image_url"))

        return jsonify(rows)
    except Exception as e:
        return jsonify({"message": "Failed to get trending products", "error": str(e)}), 500
    finally:
        cur.close()
        db.close()

# ======================
# CART ENDPOINTS
# ======================
@app.route("/cart", methods=["GET", "POST"])
def cart():
    if request.method == "GET":
        user_id = request.args.get("user_id")
        if not user_id:
            return jsonify({"success": False, "message": "user_id is required"}), 400

        db = get_db()
        cur = db.cursor(dictionary=True)
        try:
            cur.execute("""
                SELECT c.id AS cart_item_id,
                       p.id AS product_id,
                       p.name,
                       p.price,
                       p.category,
                       p.image_url,
                       p.description,
                       p.sold,
                       c.quantity,
                       p.available,   -- Add this line
                       c.status
                FROM cart c
                JOIN products p ON c.product_id = p.id
                WHERE c.user_id = %s AND c.status = 'active'
            """, (user_id,))

            cart_items = cur.fetchall()

            for item in cart_items:
                item["image_url"] = absolute_image(item.get("image_url"))

            return jsonify({"cart": cart_items}), 200

        except Exception as e:
            print("Error fetching cart:", e)
            return jsonify({"success": False, "message": "Error fetching cart"}), 500
        finally:
            cur.close()
            db.close()

    elif request.method == "POST":
        data = request.get_json(force=True)
        user_id = data.get("user_id")
        product_id = data.get("product_id")
        quantity = data.get("quantity", 1)

        if not user_id or not product_id:
            return jsonify({"success": False, "message": "user_id and product_id are required"}), 400

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute("""
                INSERT INTO cart (user_id, product_id, quantity, status)
                VALUES (%s, %s, %s, 'active')
                ON DUPLICATE KEY UPDATE
                quantity = quantity + VALUES(quantity),
                status = 'active'
            """, (user_id, product_id, quantity))
            db.commit()
            return jsonify({"success": True, "message": "Item added to cart"})
        except Exception as e:
            db.rollback()
            return jsonify({"success": False, "message": "Failed to add to cart", "error": str(e)}), 500
        finally:
            cur.close()
            db.close()


@app.route('/cart/update', methods=['POST'])
def update_cart_item():
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "No data provided"}), 400

    item_id = data.get('item_id')
    user_id = data.get('user_id')
    quantity = data.get('quantity')

    if not all([item_id, user_id, quantity]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    db = get_db()
    cur = db.cursor()
    try:
        # Verify the item belongs to the user
        cur.execute("SELECT id FROM cart WHERE id = %s AND user_id = %s", (item_id, user_id))
        if not cur.fetchone():
            return jsonify({"success": False, "message": "Cart item not found"}), 404

        # Update the quantity
        cur.execute("UPDATE cart SET quantity = %s WHERE id = %s", (quantity, item_id))
        db.commit()

        return jsonify({
            "success": True,
            "message": "Quantity updated",
            "new_quantity": quantity
        })
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route('/cart/<int:item_id>', methods=['DELETE'])
def delete_cart_item(item_id):
    # Try to get user_id from JSON body first, then from query params
    user_id = None
    if request.is_json:
        user_id = request.get_json().get('user_id')

    if user_id is None:
        user_id = request.args.get('user_id')

    if not user_id:
        return jsonify({
            'success': False,
            'message': 'user_id is required (send in JSON body or as query parameter)'
        }), 400

    db = get_db()
    cur = db.cursor()
    try:
        # Verify item belongs to user
        cur.execute("SELECT id FROM cart WHERE id = %s AND user_id = %s", (item_id, user_id))
        if not cur.fetchone():
            return jsonify({'success': False, 'message': 'Item not found'}), 404

        # Delete the item
        cur.execute("DELETE FROM cart WHERE id = %s", (item_id,))
        db.commit()
        return jsonify({'success': True, 'message': 'Item deleted'})
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        db.close()

# ======================
# ORDER ENDPOINTS
# ======================
@app.route('/orders', methods=['POST'])
def create_order():
    data = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({"success": False, "message": "user_id is required"}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        db.start_transaction()

        # Calculate values
        products = data.get('products', [])
        total_amount = sum(p['quantity'] * p['unit_price'] for p in products)
        total_items = len(products)

        # Create order
        cur.execute("""
            INSERT INTO orders (user_id, total_amount, status)
            VALUES (%s, %s, 'processing')
            """, (user_id, total_amount))
        order_id = cur.lastrowid

        # Add order items
        for product in products:
            cur.execute("SELECT id FROM products WHERE id = %s", (product['product_id'],))
            if cur.fetchone() is None:
                raise Exception(f"Product ID {product['product_id']} does not exist")

            cur.execute("""
                INSERT INTO order_items (order_id, product_id, quantity)
                VALUES (%s, %s, %s)
                """, (order_id, product['product_id'], product['quantity']))

        db.commit()

        return jsonify({
            "success": True,
            "message": "Order created successfully",
            "order_id": order_id,
            "total_amount": total_amount,
            "total_items": total_items
        })

    except Exception as e:
        db.rollback()
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": "Failed to create order",
            "error": str(e)
        }), 500
    finally:
        cur.close()
        db.close()


@app.route('/orders/user/<int:user_id>', methods=['GET'])
def get_orders_by_user(user_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        # 1️⃣ Get all orders for this user
        cursor.execute("SELECT * FROM orders WHERE user_id = %s", (user_id,))
        orders = cursor.fetchall()

        result = []

        for order in orders:
            # 2️⃣ Get all items for this order, including correct unit price from products table
            cursor.execute("""
                SELECT 
                    oi.quantity,
                    p.price AS unit_price,
                    p.name
                FROM order_items oi
                JOIN products p ON oi.product_id = p.id
                WHERE oi.order_id = %s
            """, (order['id'],))
            items = cursor.fetchall()

            # 3️⃣ Build order object
            result.append({
                "id": order['id'],
                "user_id": order['user_id'],
                "status": order['status'],
                "total_amount": float(order['total_amount']),
                "created_at": str(order['created_at']),
                "items": [
                    {
                        "name": item['name'],
                        "quantity": item['quantity'],
                        "unit_price": float(item['unit_price'])
                    } for item in items
                ]
            })
            print("Order ID:", order['id'])
            print("Fetched items:", items)

        return jsonify({"orders": result}), 200

    except Exception as e:
        print(f"Error fetching orders: {e}")
        return jsonify({"error": "Something went wrong"}), 500
# ================================
# ADMIN SIDE ORDER MANAGEMENT
# ================================

# 1. Get all orders (admin view)
@app.route('/orders', methods=['GET'])
def get_all_orders():
    try:
        admin_id = request.args.get("admin_id")  # Get admin_id from query param
        if not admin_id:
            return jsonify({"error": "admin_id required"}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Fetch orders that contain products of this admin
        cursor.execute("""
                    SELECT DISTINCT o.id, o.user_id, o.tracking_number, o.status, o.total_amount,
                                    o.created_at, o.updated_at
                    FROM orders o
                    JOIN order_items oi ON oi.order_id = o.id
                    JOIN products p ON oi.product_id = p.id
                    WHERE p.admin_id = %s
                    ORDER BY o.created_at DESC
                """, (admin_id,))

        orders = cursor.fetchall()
        return jsonify({"orders": orders}), 200

    except Exception as e:
        print(f"Error fetching orders: {e}")
        return jsonify({"error": "Something went wrong"}), 500
    finally:
        cursor.close()
        db.close()


# 2. Update order status
@app.route('/orders/<int:order_id>/status', methods=['PUT'])
def update_order_status(order_id):
    data = request.get_json()
    new_status = data.get("status")

    valid_statuses = ["processing", "in_station", "delivery", "delivered"]
    if new_status not in valid_statuses:
        return jsonify({"success": False, "message": "Invalid status"}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        cur.execute("SELECT status FROM orders WHERE id = %s", (order_id,))
        order = cur.fetchone()

        if not order:
            return jsonify({"success": False, "message": "Order not found"}), 404

        current_status = order["status"]

        # Define allowed transitions
        allowed_flow = {
            "processing": ["in_station"],   # confirm order
            "in_station": ["delivery"],     # move to delivery
            "delivery": ["delivered"]       # complete order
        }

        if new_status not in allowed_flow.get(current_status, []):
            return jsonify({"success": False,
                            "message": f"Invalid transition {current_status} → {new_status}"}), 400

        cur.execute("""
            UPDATE orders 
            SET status = %s, updated_at = %s
            WHERE id = %s
        """, (new_status, datetime.now(), order_id))
        db.commit()

        return jsonify({"success": True,
                        "message": f"Order status updated to {new_status}"}), 200

    except Exception as e:
        db.rollback()
        print("Error updating status:", e)
        return jsonify({"success": False, "message": "Failed to update status"}), 500
    finally:
        cur.close()
        db.close()

# 3. Cancel order (only if still processing)
@app.route('/orders/<int:order_id>/cancel', methods=['DELETE'])
def cancel_order(order_id):
    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        cur.execute("SELECT status FROM orders WHERE id = %s", (order_id,))
        order = cur.fetchone()

        if not order:
            return jsonify({"success": False, "message": "Order not found"}), 404

        if order["status"] != "processing":
            return jsonify({"success": False, "message": "Only processing orders can be cancelled"}), 400

        cur.execute("DELETE FROM orders WHERE id = %s", (order_id,))
        db.commit()

        return jsonify({"success": True, "message": "Order cancelled successfully"}), 200

    except Exception as e:
        db.rollback()
        print("Error cancelling order:", e)
        return jsonify({"success": False, "message": "Failed to cancel order"}), 500
    finally:
        cur.close()
        db.close()




# ========= Config =========
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "Admin_images")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


# ========= Serve Admin Images =========
@app.route("/static/Admin_images/<filename>")
def serve_admin_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# ========= Admin Profile =========
@app.route("/admin/profile/<int:admin_id>", methods=["GET"])
def get_admin_profile(admin_id):
    db = get_db()
    cur = db.cursor(dictionary=True)

    try:
        cur.execute("SELECT id, username, email, profile_image FROM admins WHERE id=%s", (admin_id,))
        admin = cur.fetchone()
        if not admin:
            return jsonify({"error": "Admin not found"}), 404

        if admin["profile_image"]:
            admin["profile_image"] = f"static/Admin_images/{admin['profile_image']}"

        # Stats: Total orders and earnings from products managed by this admin
        # This query assumes your 'products' table has an 'admin_id' column
        cur.execute("""
            SELECT
                COUNT(DISTINCT oi.order_id) AS confirmed_orders,
                COALESCE(SUM(oi.quantity * p.price), 0) AS confirmed_earnings 
                -- Assuming p.price is the price of one unit
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            WHERE o.status = 'in_station' AND p.admin_id = %s
        """, (admin_id,))
        stats = cur.fetchone()

        # Last 5 orders containing products from this admin
        # This also assumes 'products' table has an 'admin_id' column
        cur.execute("""
            SELECT DISTINCT o.id, o.total_amount, o.status, o.created_at
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            WHERE o.status = 'in_station' AND p.admin_id = %s
            ORDER BY o.created_at DESC
            LIMIT 5
        """, (admin_id,))
        recent_orders_raw = cur.fetchall() # Fetch all matching orders first

        # Optional: If you need to refine recent_orders to truly be just 5 distinct orders
        # and ensure their total_amount is correctly attributed if an order has mixed admin products
        # This part can get complex depending on business logic.
        # For now, the above query gives 5 orders that *contain* at least one product from the admin.

        return jsonify({
            "admin": admin,
            "stats": stats,
            "recent_orders": recent_orders_raw # or a processed list
        })

    except Exception as e:
        print("Error fetching admin profile:", e) # More specific error log
        return jsonify({"error": "An internal error occurred"}), 500 # Generic message to client
    finally:
        cur.close()
        db.close()


# ========= Single order with items =========
@app.route('/orders/<int:order_id>', methods=['GET'])
def get_order_details(order_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute("""
            SELECT o.id, o.user_id, o.tracking_number, o.status, o.total_amount,
                   o.created_at, o.updated_at
            FROM orders o
            WHERE o.id = %s
        """, (order_id,))
        order = cursor.fetchone()

        if not order:
            return jsonify({"error": "Order not found"}), 404

        cursor.execute("""
            SELECT 
                oi.quantity,
                p.price AS unit_price,
                p.name,
                p.image_url
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = %s
        """, (order_id,))
        items = cursor.fetchall()

        # Build response
        result = {
            "id": order['id'],
            "user_id": order['user_id'],
            "status": order['status'],
            "total_amount": float(order['total_amount']),
            "created_at": str(order['created_at']),
            "updated_at": str(order['updated_at']),
            "items": [
                {
                    "name": item['name'],
                    "quantity": item['quantity'],
                    "unit_price": float(item['unit_price']),
                    "image_url": item['image_url']  # useful for Android
                } for item in items
            ]
        }

        return jsonify({"order": result}), 200

    except Exception as e:
        print(f"Error fetching order details: {e}")
        return jsonify({"error": "Something went wrong"}), 500
    finally:
        cursor.close()
        db.close()

# # ======================
# # MESSAGING ENDPOINTS
# # ======================
# # --------------------------
# # Start or get conversation
# # --------------------------
# @app.route('/conversations/start', methods=['POST'])
# def start_conversation():
#     try:
#         data = request.get_json()
#         user_id = data.get('user_id')
#         if not user_id:
#             return jsonify({'success': False, 'error': 'Missing user_id'}), 400
#
#         conn = get_db()
#         cursor = conn.cursor(dictionary=True)
#
#         # Get default admin (first admin for simplicity)
#         cursor.execute("SELECT id FROM admins LIMIT 1")
#         admin = cursor.fetchone()
#         if not admin:
#             return jsonify({'success': False, 'error': 'No admin available'}), 500
#         admin_id = admin['id']
#
#         # Check if conversation exists
#         cursor.execute(
#             "SELECT * FROM conversations WHERE user_id=%s AND admin_id=%s LIMIT 1",
#             (user_id, admin_id)
#         )
#         conversation = cursor.fetchone()
#         if conversation:
#             return jsonify({'success': True, 'conversation_id': conversation['id'], 'message': 'Conversation exists'})
#
#         # Create new conversation
#         cursor.execute(
#             "INSERT INTO conversations (user_id, admin_id, status) VALUES (%s, %s, 'open')",
#             (user_id, admin_id)
#         )
#         conn.commit()
#         return jsonify({'success': True, 'conversation_id': cursor.lastrowid, 'message': 'Conversation created'})
#
#     except Exception as e:
#         return jsonify({'success': False, 'error': str(e)}), 500
#     finally:
#         cursor.close()
#         conn.close()
#
#
#
# # --------------------------
# # Send message (admin or user)
# # --------------------------
# @app.route('/conversations/<int:conversation_id>/messages', methods=['POST'])
# def send_message(conversation_id):
#     data = request.get_json()
#     sender_id = data.get('sender_id')
#     message = data.get('message')
#     sender_type = data.get('sender_type')
#
#     if not all([sender_id, message, sender_type]):
#         return jsonify({'success': False, 'error': 'Missing fields'}), 400
#
#     is_admin = 1 if sender_type.lower() == 'admin' else 0
#
#     db = get_db()
#     cursor = db.cursor()
#     cursor.execute('''
#         INSERT INTO messages (conversation_id, sender_id, message, sender_type, is_admin, is_read)
#         VALUES (%s, %s, %s, %s, %s, 0)
#     ''', (conversation_id, sender_id, message, sender_type, is_admin))
#     db.commit()
#     cursor.close()
#     db.close()
#     return jsonify({'success': True, 'message': 'Message sent'}), 201
#
#
#
#
#
#
# @app.route('/conversations/<int:conversation_id>/messages', methods=['GET', 'POST'])
# def conversation_messages(conversation_id):
#     conn = get_db()
#     cursor = conn.cursor(dictionary=True)
#
#     if request.method == 'GET':
#         cursor.execute('''
#             SELECT
#                 m.id,
#                 m.conversation_id,
#                 m.sender_id,
#                 m.message,
#                 m.sender_type,
#                 m.is_admin,
#                 m.reply_to_message_id,
#                 m.created_at
#             FROM messages m
#             WHERE m.conversation_id = %s
#             ORDER BY m.created_at ASC
#         ''', (conversation_id,))
#         messages = cursor.fetchall()
#
#         for msg in messages:
#             msg["is_admin"] = bool(msg["is_admin"])
#         return jsonify({"success": True, "messages": messages})
#
#     elif request.method == 'POST':
#         try:
#             data = request.get_json()
#             sender_id = data.get('sender_id')
#             message = data.get('message')
#             sender_type = data.get('sender_type')
#             reply_to = data.get('reply_to_message_id')  # optional
#
#             if not all([sender_id, message, sender_type]):
#                 return jsonify({'success': False, 'error': 'Missing required fields'}), 400
#
#             is_admin = 1 if sender_type.lower() == 'admin' else 0
#
#             cursor.execute('''
#                 INSERT INTO messages (
#                     conversation_id, sender_id, message, sender_type, is_admin, reply_to_message_id
#                 ) VALUES (%s, %s, %s, %s, %s, %s)
#             ''', (conversation_id, sender_id, message, sender_type, is_admin, reply_to))
#             conn.commit()
#
#             return jsonify({'success': True, 'message': 'Message added successfully.'}), 201
#
#         except Exception as e:
#             return jsonify({'success': False, 'error': str(e)}), 500
#
#
# @app.route('/admin/<int:admin_id>/conversations', methods=['GET'])
# def list_admin_conversations(admin_id):
#     try:
#         db = get_db()
#         cursor = db.cursor(dictionary=True)
#
#         cursor.execute('''
#             SELECT
#                 c.id as conversation_id,
#                 c.user_id,
#                 u.name as user_name,
#                 c.status,
#                 c.updated_at,
#                 (SELECT COUNT(*)
#                  FROM messages m
#                  WHERE m.conversation_id = c.id
#                    AND m.is_admin = 0
#                    AND m.is_read = 0) as unread_count
#             FROM conversations c
#             JOIN users u ON u.id = c.user_id
#             WHERE c.admin_id = %s
#             ORDER BY c.updated_at DESC
#         ''', (admin_id,))
#
#         conversations = cursor.fetchall()
#         return jsonify({"success": True, "conversations": conversations})
#
#     except Exception as e:
#         return jsonify({"success": False, "error": str(e)}), 500
#
#
#
# @app.route('/conversations/<int:conversation_id>/mark_read', methods=['POST'])
# def mark_messages_read(conversation_id):
#     try:
#         db = get_db()
#         cursor = db.cursor(dictionary=True)
#
#         # Mark all user messages as read
#         cursor.execute('''
#             UPDATE messages
#             SET is_read = 1
#             WHERE conversation_id = %s AND is_admin = 0
#         ''', (conversation_id,))
#         db.commit()
#
#         return jsonify({"success": True, "message": "Messages marked as read."})
#     except Exception as e:
#         db.rollback()
#         print(f"Error marking messages read: {e}")
#         return jsonify({"success": False, "error": str(e)}), 500
#     finally:
#         cursor.close()
#         db.close()




# @app.route('/admin/<int:admin_id>/conversations', methods=['GET'])
# def admin_conversations(admin_id):
#     db = get_db()
#     cursor = db.cursor(dictionary=True)
#     cursor.execute('''
#         SELECT c.id AS conversation_id, c.user_id, u.name AS user_name,
#                c.status, c.updated_at,
#                (SELECT COUNT(*) FROM messages m
#                 WHERE m.conversation_id = c.id AND m.is_admin=0 AND m.is_read=0) AS unread_count
#         FROM conversations c
#         JOIN users u ON u.id = c.user_id
#         WHERE c.admin_id=%s
#         ORDER BY c.updated_at DESC
#     ''', (admin_id,))
#     conversations = cursor.fetchall()
#     return jsonify({"success": True, "conversations": conversations})


# @app.route('/conversations/<int:conversation_id>/messages', methods=['GET'])
# def get_conversation_messages(conversation_id):
#     db = get_db()
#     cursor = db.cursor(dictionary=True)
#     cursor.execute('''
#         SELECT id, sender_id, message, sender_type, is_admin, is_read, created_at
#         FROM messages
#         WHERE conversation_id=%s
#         ORDER BY created_at ASC
#     ''', (conversation_id,))
#     messages = cursor.fetchall()
#     for m in messages:
#         m['is_admin'] = bool(m['is_admin'])
#     cursor.close()
#     db.close()
#     return jsonify({"success": True, "messages": messages})


# @app.route('/admin/<int:admin_id>/conversations/<int:conversation_id>/messages', methods=['POST'])
# def admin_send_message(admin_id, conversation_id):
#     data = request.get_json()
#     message = data.get("message")
#     if not message:
#         return jsonify({"success": False, "error": "Message required"}), 400
#
#     db = get_db()
#     cursor = db.cursor()
#     cursor.execute('''
#         INSERT INTO messages (conversation_id, sender_id, sender_type, is_admin, message)
#         VALUES (%s, %s, 'admin', 1, %s)
#     ''', (conversation_id, admin_id, message))
#     db.commit()
#     return jsonify({"success": True, "message": "Message sent"})





# ======================
# ORDER TRACKING ENDPOINTS
# ======================
@app.route('/order/tracking/<int:order_id>', methods=['GET'])
def get_order_tracking(order_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Get current order status
        cursor.execute("""
            SELECT status 
            FROM orders 
            WHERE id = %s
        """, (order_id,))
        order = cursor.fetchone()

        if not order:
            return jsonify({"success": False, "message": "Order not found"}), 404

        # Get status description
        status_descriptions = {
            'processing': 'Your order is being processed',
            'in_station': 'Your order is at our distribution center',
            'delivery': 'Your order is out for delivery',
            'delivered': 'Your order has been delivered'
        }

        description = status_descriptions.get(order['status'], 'Status unknown')

        return jsonify({
            "success": True,
            "status": order['status'],
            "description": description
        })

    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/tracking/update-status', methods=['POST'])
def update_tracking_status():
    """Admin endpoint to update order status"""
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        new_status = data.get('status')

        if not order_id or not new_status:
            return jsonify({"success": False, "message": "order_id and status are required"}), 400

        valid_statuses = ['processing', 'in_station', 'delivery', 'delivered']
        if new_status not in valid_statuses:
            return jsonify({"success": False, "message": "Invalid status"}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)

        # Update order status
        cursor.execute("""
            UPDATE orders
            SET status = %s
            WHERE id = %s
        """, (new_status, order_id))

        # Add to tracking history
        status_descriptions = {
            'processing': 'Order received and being processed',
            'in_station': 'Order is at our distribution center',
            'delivery': 'Out for delivery',
            'delivered': 'Delivered to customer'
        }

        cursor.execute("""
            INSERT INTO order_tracking (order_id, status, description)
            VALUES (%s, %s, %s)
        """, (order_id, new_status, status_descriptions[new_status]))

        db.commit()

        return jsonify({
            "success": True,
            "message": "Status updated",
            "order_id": order_id,
            "new_status": new_status
        })

    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        db.close()

# ======================
# FAVORITES ENDPOINTS
# ======================
@app.route("/favorites", methods=["GET", "POST", "DELETE"])
def handle_favorites():
    if request.method == "GET":
        # ... (your existing GET code remains the same)
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({'success': False, 'message': 'Missing user_id'}), 400

        db = get_db()
        cursor = db.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT p.* FROM favorites f
                JOIN products p ON f.product_id = p.id
                WHERE f.user_id = %s
            """, (user_id,))
            favorites = cursor.fetchall()

            # Convert relative image paths to absolute URLs
            for fav in favorites:
                fav["image_url"] = absolute_image(fav.get("image_url"))

            return jsonify({
                "success": True,
                "favorites": favorites
            }), 200
        except Exception as e:
            return jsonify({
                'success': False,
                'message': str(e)
            }), 500
        finally:
            cursor.close()
            db.close()

    elif request.method == "POST":
        # ... (your existing POST code remains the same)
        try:
            data = request.get_json()
            if not data:
                return jsonify({
                    'success': False,
                    'message': 'No data provided'
                }), 400

            user_id = data.get('user_id')
            product_id = data.get('product_id')

            if not user_id or not product_id:
                return jsonify({
                    'success': False,
                    'message': 'Missing user_id or product_id'
                }), 400

            db = get_db()
            cursor = db.cursor(dictionary=True)

            try:
                # Check if favorite already exists
                cursor.execute("""
                    SELECT id FROM favorites
                    WHERE user_id = %s AND product_id = %s
                """, (user_id, product_id))

                if cursor.fetchone():
                    return jsonify({
                        'success': False,
                        'message': 'Product already in favorites'
                    }), 400

                # Add new favorite
                cursor.execute("""
                    INSERT INTO favorites (user_id, product_id)
                    VALUES (%s, %s)
                """, (user_id, product_id))
                db.commit()

                return jsonify({
                    'success': True,
                    'message': 'Favorite added successfully'
                }), 200

            except Exception as e:
                db.rollback()
                return jsonify({
                    'success': False,
                    'message': str(e)
                }), 500
            finally:
                cursor.close()
                db.close()

        except Exception as e:
            return jsonify({
                'success': False,
                'message': 'Invalid request data'
            }), 400

    elif request.method == "DELETE":
        try:
            # Get user_id and product_id from query parameters
            user_id = request.args.get("user_id")
            product_id = request.args.get("product_id")

            if not user_id or not product_id:
                return jsonify({
                    "success": False,
                    "message": "Missing user_id or product_id in query parameters",
                    "received_args": dict(request.args)
                }), 400

            # Convert to int if necessary (request.args gives strings)
            try:
                user_id = int(user_id)
                product_id = int(product_id)
            except ValueError:
                 return jsonify({
                    "success": False,
                    "message": "user_id and product_id must be integers",
                }), 400


            db = get_db()
            cursor = db.cursor(dictionary=True)

            try:
                # Check if favorite exists
                cursor.execute("""
                       SELECT id FROM favorites
                       WHERE user_id = %s AND product_id = %s
                   """, (user_id, product_id))
                favorite = cursor.fetchone()

                if not favorite:
                    return jsonify({
                        "success": False,
                        "message": "Favorite not found"
                    }), 404

                # Delete the favorite
                cursor.execute("""
                       DELETE FROM favorites
                       WHERE user_id = %s AND product_id = %s
                   """, (user_id, product_id))
                db.commit()

                return jsonify({
                    "success": True,
                    "message": "Favorite removed",
                    "deleted_favorite_for_user": user_id,
                    "deleted_product_id": product_id
                }), 200

            except Exception as e:
                db.rollback()
                return jsonify({
                    "success": False,
                    "message": f"Database error: {str(e)}"
                }), 500
            finally:
                cursor.close()
                db.close()

        except Exception as e:
            return jsonify({
                "success": False,
                "message": f"Server error: {str(e)}"
            }), 500

# ======================
# AUTHENTICATION ENDPOINTS FOR ADMIN
# ======================

@app.route("/register_admin", methods=["POST"])
def register_admin():
    try:
        data = request.get_json(force=True)
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        profile_image_base64 = data.get("profile_image")  # ensure key matches client

        if not all([name, email, password, profile_image_base64]):
            return jsonify({"success": False, "message": "Missing required fields"}), 400

        # Decode and save image
        filename = f"admin_{int(datetime.now().timestamp())}.jpg"
        image_folder = os.path.join("static", "admin_images")
        os.makedirs(image_folder, exist_ok=True)
        image_path = os.path.join(image_folder, filename)
        with open(image_path, "wb") as f:
            f.write(base64.b64decode(profile_image_base64))

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        db = get_db()
        cursor = db.cursor()

        # Check if email exists
        cursor.execute("SELECT id FROM admins WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"success": False, "message": "Email already registered"}), 409

        # Insert admin into database
        sql = """
            INSERT INTO admins (username, email, password, profile_image, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """
        cursor.execute(sql, (name, email, hashed_password.decode('utf-8'), filename))
        db.commit()

        cursor.close()
        db.close()

        return jsonify({"success": True, "message": "Admin registered successfully"})

    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": "Server error: " + str(e)}), 500


@app.route("/login_admin", methods=["POST"])
def login_admin():
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "Email and password are required"}), 400

    db = get_db()
    cur = db.cursor(dictionary=True)
    try:
        cur.execute("SELECT * FROM admins WHERE email = %s", (email,))
        user = cur.fetchone()

        if user and bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({
                "success": True,
                "message": "Login success",
                "user_id": user["id"],
                "name": user["username"]
            })
        return jsonify({"success": False, "message": "Invalid email or password"}), 401
    except Exception as e:
        return jsonify({"success": False, "message": "Login failed", "error": str(e)}), 500
    finally:
        cur.close()
        db.close()



# Verify email for admins
@app.route("/verify_email_admin", methods=["POST"])
def verify_email_admin():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        if not email:
            return jsonify({"success": False, "message": "Email required"}), 400

        db = get_db()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, username FROM admins WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        db.close()

        if user:
            return jsonify({"success": True, "message": "Email found", "username": user["username"]})
        return jsonify({"success": False, "message": "Email not found"}), 404
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500


# Update password for admins
@app.route("/update_password_admin", methods=["POST"])
def update_password_admin():
    try:
        data = request.get_json(force=True)
        email = data.get("email")
        new_password = data.get("new_password")
        if not email or not new_password:
            return jsonify({"success": False, "message": "Email and new password required"}), 400

        hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id FROM admins WHERE email = %s", (email,))
        if not cur.fetchone():
            cur.close()
            db.close()
            return jsonify({"success": False, "message": "Email not found"}), 404

        cur.execute("UPDATE admins SET password = %s, update_time = %s WHERE email = %s",
                    (hashed, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), email))
        db.commit()
        cur.close()
        db.close()
        return jsonify({"success": True, "message": "Password updated"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"success": False, "message": str(e)}), 500



# ================================
# ADMIN PROFILE & STATISTICS (CONFIRMED ONLY)
# ================================



# @app.route('/admin/invoice/<int:order_id>', methods=['GET'])
# def generate_invoice(order_id):
#     try:
#         db = get_db()
#         cursor = db.cursor(dictionary=True)
#
#         # Get order details
#         cursor.execute("""
#             SELECT o.*, a.username as admin_name, a.email as admin_email
#             FROM orders o, admins a
#             WHERE o.id = %s AND a.id = 1
#         """, (order_id,))
#         order = cursor.fetchone()
#
#         if not order:
#             return jsonify({"error": "Order not found"}), 404
#
#         # Get order items with details
#         cursor.execute("""
#             SELECT p.name, oi.quantity, p.price, (oi.quantity * p.price) as total,
#                    p.category, p.description
#             FROM order_items oi
#             JOIN products p ON oi.product_id = p.id
#             WHERE oi.order_id = %s
#         """, (order_id,))
#         items = cursor.fetchall()
#
#         # Get admin business info
#         cursor.execute("SELECT username, email, created_at as business_since FROM admins WHERE id = 1")
#         admin_info = cursor.fetchone()
#
#         invoice_data = {
#             "invoice_info": {
#                 "invoice_number": f"INV-{order_id}-{datetime.now().strftime('%Y%m%d')}",
#                 "invoice_date": datetime.now().strftime("%B %d, %Y"),
#                 "due_date": (datetime.now() + timedelta(days=30)).strftime("%B %d, %Y")
#             },
#             "business_info": {
#                 "name": admin_info['username'],
#                 "email": admin_info['email'],
#                 "business_since": admin_info['business_since'].strftime("%Y") if admin_info[
#                     'business_since'] else "2025"
#             },
#             "order_info": {
#                 "order_id": order['id'],
#                 "order_date": order['created_at'].strftime("%B %d, %Y") if order['created_at'] else "N/A",
#                 "status": order['status'],
#                 "customer_id": order['user_id']
#             },
#             "items": items,
#             "summary": {
#                 "subtotal": float(order['total_amount']),
#                 "tax": 0.00,  # You can add tax calculation if needed
#                 "total": float(order['total_amount']),
#                 "amount_paid": float(order['total_amount']),
#                 "balance_due": 0.00
#             }
#         }
#
#         return jsonify(invoice_data), 200
#
#     except Exception as e:
#         print(f"Error generating invoice: {e}")
#         return jsonify({"error": "Something went wrong"}), 500
#     finally:
#         cursor.close()
#         db.close()


# Allowed extensions for image files
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route("/products", methods=["POST"])
def add_product():
    print("Files received:", list(request.files.keys()))
    print("Form data received:", list(request.form.keys()))

    if 'image' not in request.files:
        return jsonify({"message": "No image file part"}), 400

    image_file = request.files['image']
    if image_file.filename == '':
        return jsonify({"message": "No selected image file"}), 400

    if not allowed_file(image_file.filename):
        return jsonify({"message": "Unsupported file extension"}), 400

    name = request.form.get("name")
    price = request.form.get("price")
    category = request.form.get("category", "")
    description = request.form.get("description", "")
    total_item = int(request.form.get("total_item", 0))
    admin_id = int(request.form.get("admin_id", 0))  # new


    if not name or not price:
        return jsonify({"message": "Name and price are required"}), 400

    try:
        price = float(price)
    except ValueError:
        return jsonify({"message": "Price must be a number"}), 400

    # Save image to /static/Add_products
    filename = secure_filename(image_file.filename)
    save_folder = os.path.join(current_app.root_path, "static", "Add_products")
    os.makedirs(save_folder, exist_ok=True)
    image_path = os.path.join(save_folder, filename)

    # To avoid overwriting existing files, you might want to rename file uniquely:
    import time
    filename = f"{int(time.time())}_{filename}"
    image_path = os.path.join(save_folder, filename)
    image_file.save(image_path)

    # Create URL path relative to server root
    image_url = f"/static/Add_products/{filename}"

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
            INSERT INTO products 
                (name, price, category, image_url, description, total_item, admin_id, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
        """, (name, price, category, image_url, description, total_item, admin_id))

        db.commit()
        return jsonify({"success": True, "message": "Product added"})
    except Exception as e:
        db.rollback()
        return jsonify({"message": "Failed to add product", "error": str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route("/products/<int:product_id>/stock", methods=["PUT"])
def update_stock(product_id):
    data = request.get_json()
    total_item = data.get("total_item")

    if total_item is None:
        return jsonify({"success": False, "message": "total_item value required"}), 400

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
                    UPDATE products
                    SET total_item = %s,
                        
                        updated_at = NOW()
                    WHERE id = %s
                """, (total_item, product_id))
        db.commit()
        return jsonify({"success": True, "message": "Stock updated"})
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cur.close()
        db.close()


@app.route("/products/<int:product_id>", methods=["DELETE"])
def delete_product(product_id):
    print("Request Content-Type:", request.content_type)
    print("Request form data:", request.form)
    print("Request files:", request.files)

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM products WHERE id = %s", (product_id,))
        db.commit()
        return jsonify({"message": "Product deleted successfully"})
    except Exception as e:
        db.rollback()
        return jsonify({"message": "Failed to delete product", "error": str(e)}), 500
    finally:
        cur.close()
        db.close()

@app.route("/products/<int:product_id>", methods=["PUT"])
def update_product(product_id):
    data = request.get_json()

    data = request.get_json()
    name = data.get("name")
    price = data.get("price")
    category = data.get("category", "")
    image_url = data.get("image_url", "")
    description = data.get("description", "")
    total_item = data.get("total_item", 0)

    if not all([name, price, total_item is not None]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("""
                        UPDATE products
                        SET name = %s,
                            price = %s,
                            category = %s,
                            image_url = %s,
                            description = %s,
                            total_item = %s,
                            updated_at = NOW()
                        WHERE id = %s
                    """, (name, price, category, image_url, description, total_item, product_id))
        db.commit()
        return jsonify({"success": True, "message": "Product updated"})
    except Exception as e:
        db.rollback()
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cur.close()
        db.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)