pypi: dist
	twine upload dist/*
	
dist: clean
	./setup.py sdist bdist_wheel

clean:
	-rm -rf *.egg-info build dist

.PHONY: clean
