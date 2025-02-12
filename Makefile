.PHONY: install migrate migrations docker-up docker-down run

install:
	poetry install --no-root

migrate:
	poetry run python manage.py migrate

migrations:
	poetry run python manage.py makemigrations

docker-up:
	docker-compose up --build -d

docker-down:
	docker-compose down

run:
	poetry run python manage.py runserver 0.0.0.0:8000
