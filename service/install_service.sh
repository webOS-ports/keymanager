
#!/bin/sh

FOLDER="org.webosports.service.keymanager"
SID="com.palm.keymanager"


echo "Removing old Service files...."

# Remove the dbus service
#rm -f /usr/share/dbus-1/system-services/${SID}.service
#rm -f /usr/share/dbus-1/services/${SID}.service
rm -f /usr/share/dbus-1/system-services/${SID2}.service
rm -f /usr/share/dbus-1/services/${SID2}.service


# Remove the ls2 roles
rm -f /usr/share/ls2/roles/prv/${SID}.json
rm -f /usr/share/ls2/roles/pub/${SID}.json
rm -f /usr/share/ls2/roles/prv/${SID2}.json
rm -f /usr/share/ls2/roles/pub/${SID2}.json

# Stop the service if running
/usr/bin/killall -9 ${SID} || true
/usr/bin/killall -9 ${SID2} || true

echo "Installing Service...."

# Install the dbus service
#cp /usr/palm/services/${SID}/sysbus/${SID}.service.pub /usr/share/dbus-1/services/${SID}.service
#cp /usr/palm/services/${SID}/sysbus/${SID}.service.prv /usr/share/dbus-1/system-services/${SID}.service
cp /usr/palm/services/${SID}/sysbus/${SID2}.service.pub /usr/share/dbus-1/services/${SID2}.service
cp /usr/palm/services/${SID}/sysbus/${SID2}.service.prv /usr/share/dbus-1/system-services/${SID2}.service

# Install the ls2 roles
#cp /usr/palm/services/${SID}/sysbus/${SID}.json.prv /usr/share/ls2/roles/prv/${SID}.json
#cp /usr/palm/services/${SID}/sysbus/${SID}.json.pub /usr/share/ls2/roles/pub/${SID}.json
cp /usr/palm/services/${SID}/sysbus/${SID2}.json.prv /usr/share/ls2/roles/prv/${SID2}.json
cp /usr/palm/services/${SID}/sysbus/${SID2}.json.pub /usr/share/ls2/roles/pub/${SID2}.json

echo "Done"
