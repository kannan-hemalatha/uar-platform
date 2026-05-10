# run.py
from app import create_app, db

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()    # creates uar_dev.db locally if it does not exist
    app.run(host='0.0.0.0', port=8080, debug=True)

