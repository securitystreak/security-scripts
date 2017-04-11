#!/usr/bin/python
#
# Copyright (C) 2015 Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys, subprocess
import sqlite3 as lite
from prettytable import from_db_cursor


def dump_database(backup_dir):

    # dumping the password/pin from the device
    print "Dumping contacts database ..."

    contactsDB = subprocess.Popen(['adb', 'pull', '/data/data/com.android.providers.contacts/databases/contacts2.db', 
        backup_dir], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    contactsDB.wait()


def get_content(backup_dir):

    # getting the content from the contacts database
    con = lite.connect(backup_dir + '/contacts2.db')
    cur = con.cursor()    
    cur.execute("SELECT contacts._id AS _id,contacts.custom_ringtone AS custom_ringtone, name_raw_contact.display_name_source AS display_name_source, name_raw_contact.display_name AS display_name, name_raw_contact.display_name_alt AS display_name_alt, name_raw_contact.phonetic_name AS phonetic_name, name_raw_contact.phonetic_name_style AS phonetic_name_style, name_raw_contact.sort_key AS sort_key, name_raw_contact.phonebook_label AS phonebook_label, name_raw_contact.phonebook_bucket AS phonebook_bucket, name_raw_contact.sort_key_alt AS sort_key_alt, name_raw_contact.phonebook_label_alt AS phonebook_label_alt, name_raw_contact.phonebook_bucket_alt AS phonebook_bucket_alt, has_phone_number, name_raw_contact_id, lookup, photo_id, photo_file_id, CAST(EXISTS (SELECT _id FROM visible_contacts WHERE contacts._id=visible_contacts._id) AS INTEGER) AS in_visible_group, status_update_id, contacts.contact_last_updated_timestamp, contacts.last_time_contacted AS last_time_contacted, contacts.send_to_voicemail AS send_to_voicemail, contacts.starred AS starred, contacts.pinned AS pinned, contacts.times_contacted AS times_contacted, (CASE WHEN photo_file_id IS NULL THEN (CASE WHEN photo_id IS NULL OR photo_id=0 THEN NULL ELSE 'content://com.android.contacts/contacts/'||contacts._id|| '/photo' END) ELSE 'content://com.android.contacts/display_photo/'||photo_file_id END) AS photo_uri, (CASE WHEN photo_id IS NULL OR photo_id=0 THEN NULL ELSE 'content://com.android.contacts/contacts/'||contacts._id|| '/photo' END) AS photo_thumb_uri, 0 AS is_user_profile FROM contacts JOIN raw_contacts AS name_raw_contact ON(name_raw_contact_id=name_raw_contact._id)")
    pt = from_db_cursor(cur)
    con.close()

    print pt    

    '''
    print "\033[0;32mid, custom_ringtone, display_name_source, display_name, display_name_alt, phonetic_name, phonetic_name_style, sort_key, phonebook_label, phonebook_bucket, sort_key_alt, phonebook_label_alt, phonebook_bucket_alt, has_phone_number, name_raw_contact_id, lookup, photo_id, photo_file_id, in_visible_group, status_update_id, contact_last_updated_timestamp, last_time_contacted, send_to_voicemail, starred, pinned, times_contacted, photo_uri, photo_thumb_uri, is_user_profile\033[m"

    for entry in data:
        print "\033[0;32m" + str(entry) + "\033[m"
    '''
    
if __name__ == '__main__':

    # check if device is connected and adb is running as root
    if subprocess.Popen(['adb', 'get-state'], stdout=subprocess.PIPE).communicate(0)[0].split("\n")[0] == "unknown":
        print "no device connected - exiting..."
        sys.exit(2)

    # starting to create the output directory
    backup_dir = sys.argv[1]

    try:
        os.stat(backup_dir)
    except:
        os.mkdir(backup_dir)
    
    dump_database(backup_dir)
    get_content(backup_dir)
