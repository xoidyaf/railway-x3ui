from app import app, db, Admin
from werkzeug.security import generate_password_hash
import getpass

def create_admin():
    with app.app_context():
        username = 'admin'
        password = getpass.getpass("رمز عبور ادمین را وارد کنید: ")
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            print(f"⚠️ ادمین {username} وجود دارد.")
            choice = input("تغییر رمز؟ (y/n): ")
            if choice.lower() == 'y':
                admin.password = generate_password_hash(password)
                db.session.commit()
                print("✅ رمز تغییر کرد.")
        else:
            admin = Admin(username=username, password=generate_password_hash(password))
            db.session.add(admin)
            db.session.commit()
            print(f"✅ ادمین {username} ساخته شد.")

if __name__ == '__main__':
    create_admin()
