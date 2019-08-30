centrifuge-cli: The official Python CLI for Centrifuge
=======================================================

Centrifuge is an automated firmware analysis platform. It allows users to upload
their firmware images to be analyzed for various security issues. This utility
gives users the ability to interact and automate tasks via the Centrifuge
RESTful API.

Features
--------

- Upload firmware
- Delete firmware reports
- Query firmware analysis results
- Search for firmware uploads

Quick Start
-----------

Check your Python version (must be 3.6 or later):

.. code-block:: bash

    $ python --version

To install the Centrifuge CLI, simply:

.. code-block:: bash

    $ pip install centrifuge-cli

Configure your environment:

.. code-block:: bash

    $ export CENTRIFUGE_APIKEY=xxxx
    $ export CENTRIFUGE_URL=https://centrifuge.refirmlabs.com # change this if you're single tenant or on-premise

To query the list of available reports:

.. code-block:: bash

    $ centrifuge reports list

Under the hood the Centrifuge CLI is using python Pandas data frames to report
the results to the user. Since the API is json, which has heirarchical structure
to it, we have chosen to flatten all the results into a column/row format for
viewing inside of a terminal or for importing into spreadsheets, etc. However
the cli can also output CSV, and the original json results. For example:

CSV:

.. code-block:: bash

    $ centrifuge --outfmt=csv reports list

JSON:

.. code-block:: bash

    $ centrifuge --outfmt=json reports list

When generating the human-readable Pandas output or when genering CSV you have
the option of choosing which columns you wish to export. For example, to display
only the original filename and model number of the firmware that was uploaded: 

.. code-block:: bash

    $ centrifuge -foriginalFilename -fdevice reports list


Uploading Firmware
------------------
Uploading firmware to centrifuge is quite simple. All you need to do is supply
make/model/version and the file you want to upload:

.. code-block:: bash

    $ centrifuge upload --make=Linksys --model=E1200 --version=1.0.04 /path/to/FW_E1200_v1.0.04.001_US_20120307.bin

Searching Through Firmware Uploads
----------------------------------

You can search through the uploaded firmware for keywords in username, filename, make, model, etc:

.. code-block:: bash

    $ centrifuge reports search "Linksys"

Querying Report Results
------------------------

All the following commands require access to what we refer to as a "UFID" or
Upload File ID. This ID can be seen through the web interface, its also the last
part of the URL when viewing a report, it is also the ``id`` field when running
the ``centrifuge reports list`` command above. It should also be noted that all of
these commands also support the ``--outfmt`` argument so you can export to CSV and
to JSON. However be aware that these arguments are positional in nature, you
must supply the ``--outfmt`` argument between ``centrifuge`` and ``report`` on the
command line or it will not be accepted. 

You can see the available commands by viewing the help output:

.. code-block:: bash

  $ centrifuge report --help
  Usage: centrifuge report [OPTIONS] COMMAND [ARGS]...

  Options:
    --ufid ID  Centrifuge report ID  [required]
    --help     Show this message and exit.

  Commands:
    code-emulated
    code-static
    code-summary
    crypto
    delete
    guardian
    info
    passhash
    sbom

Get basic information about the report (User, Make, Model, Version, filename, etc):

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> info

Get Guardian Results:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> guardian

Get Password Hashes:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> passhash

Get Crypto Keys:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> crypto

Get SBOM Results:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> sbom

The code analysis section is a little bit more complicated, since the data is
more structured. To understand how to access this data you need to understand
that when we process a firmware we must extract it first, each time we extract a
filesystem or file container those groups of files are given an ``extraction ID``
or ``EXID``. To get code analysis results for an individual file you must know the
``EXID`` and the file's ``PATH`` within that EXID. Luckily there is a ``code-summary``
command which will give you the data you need to find into the ``code-static`` and
``code-emulated`` commands.
 
Get a Summary of the Code Analysis:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> code-summary

When looking at the results above from the ``code-summary`` command you need to
record the ``exid`` and ``path`` (*NOT* ``fullPath``), to feed into the next two commands. 

Get static code analysis results:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> code-static --exid=<EXID> --path=<PATH>


Get emulated code analysis results:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> code-emulated --exid=<EXID> --path=<PATH>


Deleting Firmware Uploads
-------------------------

Deleting a previously uploaded firmware is an unrecoverable action. Unlike the
web interface the command line interface will not prompt you if you are sure.
So use this command carefully. 

To delete a firmware:

.. code-block:: bash

    $ centrifuge report --ufid=<REPORT_ID> delete
