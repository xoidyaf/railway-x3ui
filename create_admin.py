```python
from app import app, db, Admin
from werkzeug.security import generate_password_hash
import getpass

def create_admin():
    with app.app_context():
        username = 'admin'
        password = getpass.getpass("رمز عبور ادمین را وارد کنید: ")
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            print(f"⚠️ ادمین با نام {username} قبلاً وجود دارد.")
            choice = input("آیا می‌خواهید رمز آن را تغییر دهید؟ (y/n): ")
            if choice.lower() == 'y':
                admin.password = generate_password_hash(password)
                db.session.commit()
                print(f"✅ رمز عبور ادمین {username} به‌روزرسانی شد.")
        else:
            admin = Admin(username=username, password=generate_password_hash(password))
            db.session.add(admin)
            db.session.commit()
            print(f"✅ ادمین {username} با موفقیت ساخته شد.")

if __name__ == '__main__':
    create_admin()
```

---
