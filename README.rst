centrifuge-cli: The official Python library and CLI for Centrifuge
======================================================

Centrifuge is an automated firmware analysis platform. It allows users to upload their firmware images
to be analyzed for various security issues. This utility gives users the ability to interact and automate
tasks via the Centrifuge RESTful API. 

Features
--------

- Upload firmware
- Delete firmware reports
- Query firmware analysis results
- Search for firmware uploads

Quick Start
-----------


To install the Centrifuge CLI, simply:

.. code-block:: bash

    $ pip install centrifuge-cli

To query the list of available reports:

.. code-block:: bash
    
    $ export CENTRIFUGE_API_KEY=xxxx
    $ centrifuge reports list

Under the hood the Centrifuge CLI is using python Pandas data frames to report the results to the user. Since the API is json, which
has heirarchical structure to it, we have chosen to flatten all the results into a column/row format for viewing inside of a terminal 
or for importing into spreadsheets, etc. However the cli can also output CSV, and the original json results. For example:

CSV:
.. code-block:: bash
    
    $ centrifuge --outfmt=csv reports list

JSON:
.. code-block:: bash
    
    $ centrifuge --outfmt=json reports list

When generating the human-readable Pandas output or when genering CSV you have the option of choosing which columns you wish to export.
For example, to display only the original filename and model number of the firmware that was uploaded: 
.. code-block:: bash
    
    $ centrifuge -foriginalFilename -fdevice reports list


Uploading Firmware
------------------
Uploading firmware to centrifuge is quite simple. All you need to do is supply make/model/version and the file you want to upload:

.. code-block:: bash
    
    $ centrifuge upload --make=Linksys --model=E1200 --version=1.0.04 /path/to/FW_E1200_v1.0.04.001_US_20120307.bin

Searching Through Firmware Uploads
----------------------------------

Querying Report Results
------------------------

Deleting Firmware Uploads
-------------------------