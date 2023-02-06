# suit-generator

Implementation of SUIT envelope generator based on input yaml or json string.

## Installation
```
git clone https://github.com/NordicSemiconductor/suit-generator.git
cd suit-generator
pip install .
```

## Testing
```
cd suit-generator/tests
pytest
```

## Basic usage
```
suit-genrator --help
```

## Package build and release
```
python setup.py --version
git tag vX.Y.Z
python -m build
```

ci-test
