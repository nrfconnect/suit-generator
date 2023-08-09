# suit-generator

Implementation of SUIT envelope generator based on input yaml or json string.

## Installation
```shell
git clone https://github.com/NordicSemiconductor/suit-generator.git
cd suit-generator
pip install .
```

## Testing
```shell
pip install -r tests/requirements-test.txt
cd suit-generator/tests
pytest
```

## Basic usage
```shell
suit-generator --help
```

### Envelope creation
```shell
cd examples/input_files
dd if=/dev/zero of=file.bin bs=1024 count=1
suit-generator create --input-file example/input_files/envelope_1.json --output-file envelope.suit
```

### Key generation
```shell
suit-generator keys --output-file key
```

### Key conversion
```shell
suit-generator convert --input-file key_private.pem --output-file key_public.c
```

### Adding signature
```shell
suit-generator sign --input-file envelope.suit --output-file envelope_signed.suit --private-key key_private.pem
```

## Package build and release
```shell
python setup.py --version
git tag vX.Y.Z
python -m build
```

## Documentation build
```shell
pip install ./
pip install -r doc/requirements-doc.txt
sphinx-build -b html doc/source/ doc/build/html
```

