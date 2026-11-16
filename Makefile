.PHONY: test lint install run replay clean image

PYTHON ?= python3
IFACE ?= eth0

test:
	$(PYTHON) -m unittest discover -s . -p 'test_*.py' -v

lint:
	$(PYTHON) -m flake8 arpwatchdog.py test_arpwatchdog.py --max-line-length=110

install:
	$(PYTHON) -m pip install '.[live]'

run: install
	sudo -E $(PYTHON) -m arpwatchdog --interface $(IFACE)

replay:
	$(PYTHON) -m arpwatchdog --replay $(FILE) --format text

image:
	docker build -t arpwatchdog .

image-run:
	docker run --rm -it --cap-add=NET_RAW --network=host arpwatchdog -i $(IFACE)

clean:
	rm -rf build dist *.egg-info __pycache__ .pytest_cache
	find . -name '*.pyc' -delete
