# Fuzzing
Basic scripts for suit-generator fuzzing.

All scripts uses atheris fuzzer available here: https://github.com/google/atheris

## How to run
```shell
cd tests/fuzz
pip install -r requirements-fuzz.txt
python fuzz_suit_obj.py
python fuzz_suit_tstr.py
python fuzz_suit_yaml.py
```

## How to limit amount of runs
```shell
python fuzz_suit_yaml.py -atheris_runs=1000000
```

## How to read results
Atheris will stop fuzzing if:
- atheris_runs has been reached
- no handled exception has been raised
- exit() has been called from script

Results (binary payloads) are available in the tests/fuzz folder under crash-<number> names