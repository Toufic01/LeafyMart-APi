import traceback
from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import bcrypt
import json
import os
import base64
from datetime import datetime
from flask_socketio import SocketIO, emit

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database connection
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        passwd="",
        database="leafymart"
    )

# Helper function for image URLs
def absolute_image(db_value: str | None) -> str:
    if not db_value or db_value.lower() == "null":
        return request.host_url.rstrip("/") + "/static/images/default.jpg"
    if db_value.startswith("http"):
        return db_value
    if db_value.startswith("static/"):
        return request.host_url.rstrip("/") + "/" + db_value
    return request.host_url.rstrip("/") + "/static/images/" + db_value

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
            cur.execute("SELECT * FROM products WHERE category = %s", (category,))
        elif search_query:
            cur.execute("SELECT * FROM products WHERE name LIKE %s", (f"%{search_query}%",))
        else:
            cur.execute("SELECT * FROM products")

        rows = cur.fetchall()
        for row in rows:
            row["image_url"] = absolute_image(row.get("image_url"))

        return jsonify(rows)
    except Exception as e:
        return jsonify({"message": "Failed to get products", "error": str(e)}), 500
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
                       p.rating,
                       p.sold,
                       c.quantity,
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
        cursor.execute("""
            SELECT o.id as order_id,
                   o.created_at as order_date,
                   o.status,
                   o.total_amount,
                   oi.product_id,
                   oi.quantity
            FROM orders o
            JOIN order_items oi ON o.id = oi.order_id
            WHERE o.user_id = %s
            ORDER BY o.created_at DESC
            """, (user_id,))
        orders = cursor.fetchall()
        if not orders:
            return jsonify({"orders": []}), 200
        return jsonify({"orders": orders}), 200
    except Exception as e:
        print(f"Error fetching orders for user_id {user_id}: {e}")
        return jsonify({"error": "Something went wrong"}), 500

# ======================
# MESSAGING ENDPOINTS
# ======================

@app.route('/conversations/start', methods=['POST'])
def start_conversation():
    try:
        data = request.get_json()
        user_id = data.get('user_id')

        if not user_id:
            return jsonify({'success': False, 'error': 'Missing user_id'}), 400

        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # Get default admin ID (you can customize this)
        cursor.execute("SELECT id FROM admins LIMIT 1")
        admin = cursor.fetchone()
        if not admin:
            return jsonify({'success': False, 'error': 'No admin available'}), 500
        admin_id = admin['id']

        # Check if conversation exists
        cursor.execute(
            "SELECT * FROM conversations WHERE user_id = %s AND admin_id = %s LIMIT 1",
            (user_id, admin_id)
        )
        conversation = cursor.fetchone()

        if conversation:
            return jsonify({'success': True, 'conversation_id': conversation['id'], 'message': 'Conversation exists'})

        # Create new conversation
        cursor.execute(
            "INSERT INTO conversations (user_id, admin_id, status) VALUES (%s, %s, 'open')",
            (user_id, admin_id)
        )
        conn.commit()
        new_id = cursor.lastrowid

        return jsonify({'success': True, 'conversation_id': new_id, 'message': 'Conversation created'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/conversations/<int:conversation_id>/messages', methods=['GET', 'POST'])
def conversation_messages(conversation_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'GET':
        cursor.execute('''
            SELECT 
                m.id,
                m.conversation_id,
                m.sender_id,
                m.message,
                m.sender_type,
                m.is_admin,
                m.reply_to_message_id,
                m.created_at
            FROM messages m
            WHERE m.conversation_id = %s
            ORDER BY m.created_at ASC
        ''', (conversation_id,))
        messages = cursor.fetchall()

        for msg in messages:
            msg["is_admin"] = bool(msg["is_admin"])
        return jsonify({"success": True, "messages": messages})

    elif request.method == 'POST':
        try:
            data = request.get_json()
            sender_id = data.get('sender_id')
            message = data.get('message')
            sender_type = data.get('sender_type')
            reply_to = data.get('reply_to_message_id')  # optional

            if not all([sender_id, message, sender_type]):
                return jsonify({'success': False, 'error': 'Missing required fields'}), 400

            is_admin = 1 if sender_type.lower() == 'admin' else 0

            cursor.execute('''
                INSERT INTO messages (
                    conversation_id, sender_id, message, sender_type, is_admin, reply_to_message_id
                ) VALUES (%s, %s, %s, %s, %s, %s)
            ''', (conversation_id, sender_id, message, sender_type, is_admin, reply_to))
            conn.commit()

            return jsonify({'success': True, 'message': 'Message added successfully.'}), 201

        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/admin/<int:admin_id>/conversations', methods=['GET'])
def list_admin_conversations(admin_id):
    try:
        db = get_db()
        cursor = db.cursor(dictionary=True)

        cursor.execute('''
            SELECT 
                c.id as conversation_id,
                c.user_id,
                u.name as user_name,   -- assuming a `users` table
                c.status,
                c.updated_at
            FROM conversations c
            JOIN users u ON u.id = c.user_id
            WHERE c.admin_id = %s
            ORDER BY c.updated_at DESC
        ''', (admin_id,))

        conversations = cursor.fetchall()
        return jsonify({"success": True, "conversations": conversations})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)