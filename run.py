from app import app

if __name__ == "__main__":
    app.run(debug=False, threaded=True, use_reloader=False, port=5000)