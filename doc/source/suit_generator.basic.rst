suit-generator basic usage
==========================
suit-generator can be used as a command line tool or python module.

Command line usage:

 .. code-block:: python

   suit-generator --help

Python module usage:

 * envelope creation:

 .. code-block:: python

   from suit_generator import envelope
   envelope = SuitEnvelope()
   envelope.load('input.yaml')
   envelope.dump('output.cbor')

 * cbor to json conversion:

 .. code-block:: python

   from suit_generator import envelope
   envelope = SuitEnvelope()
   envelope.load('input.suit')
   envelope.dump('output.json')

suit_generator command line interface
-------------------------------------
Subcommand command
***********************

.. argparse::
   :module: suit_generator.args
   :func: _parser
   :prog: suit-generator

suit-generator python module
----------------------------

.. automodule:: suit_generator.envelope
   :members:
   :exclude-members: FileTypeException
   :undoc-members:

suit-generator python module (cmd_create)
-----------------------------------------

.. automodule:: suit_generator.cmd_create
   :members:
   :exclude-members:
   :undoc-members:

suit-generator python module (cmd_parse)
----------------------------------------

.. automodule:: suit_generator.cmd_parse
   :members:
   :exclude-members:
   :undoc-members:

suit-generator python module (cmd_sign)
---------------------------------------

.. automodule:: suit_generator.cmd_sign
   :members:
   :exclude-members: Sign, LocalSigner
   :undoc-members:

suit-generator python module (cmd_image)
----------------------------------------

.. automodule:: suit_generator.cmd_image
   :members:
   :exclude-members:
   :undoc-members:

suit-generator python module (cmd_convert)
------------------------------------------

.. automodule:: suit_generator.cmd_convert
   :members:
   :exclude-members:
   :undoc-members:

