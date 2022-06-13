# Getting Started

1. Clone the Project to your local system

    ``` git clone project ```
2. Create a virtual environment with virtualenv or pipenv (I'm using virtualenv here)

    ``` virtualenv venv && source venv/bin/activate ```


3. Install all the requirements from requirements.txt file

    ``` pip install -r requirements.txt ```

4. Run migrations

    ``` python manage.py makemigrations && migrate ```

4. You are ready to run the project

    ``` python manage.py runserver ```

