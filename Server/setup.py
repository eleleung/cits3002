######################################
#   CITS3002 PROJECT PARTICIPANTS:   #
#------------------------------------#
# Eleanor Leung   |	    21149831     #
# Aiden Ziegelaar |     21333223     #
# Matthew Cooper  |     20933403     #
######################################

import os
import pip
import config

# Check if external_modules exists
if os.path.exists(os.path.join(os.getcwd(), "external_modules")):
    print("Non-administrative subdirectory found")
else:
    os.mkdir(os.path.join(os.getcwd(), "external_modules"))

# Check if pyOpenSSL installed
if os.path.exists(os.path.join(os.getcwd(), "external_modules", "OpenSSL")):
    print("pyOpenSSL already installed")
else:
    print("Installing pyOpenSSL")
    pip.main(["install", "-t", os.path.join(os.getcwd(), "external_modules", "OpenSSL"), "pyOpenSSL"])
