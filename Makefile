.PHONY: setup train run docker-build docker-run clean test

setup:
\tpython -m pip install --upgrade pip
\tpip install -r requirements.txt

train:
\tpython train_model.py

run:
\tstreamlit run app/app.py --server.port=8501 --server.address=0.0.0.0

docker-build:
\tdocker build -t cognitive-soar:latest .

docker-run:
\tdocker run --rm -p 8501:8501 cognitive-soar:latest

test:
\tpython -m unittest -v

clean:
\trm -rf __pycache__ artifacts/*.pkl artifacts/*.json .pytest_cache .mypy_cache