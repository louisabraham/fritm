pypi: dist
	twine upload dist/*
	
dist: doc
	-rm dist/*
	./setup.py sdist bdist_wheel

clean:
	rm -rf *.egg-info build dist

doc: README.md
	pandoc README.md -o README.rst