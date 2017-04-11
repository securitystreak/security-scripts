import pypff

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.01
__description__ = 'This scripts handles processing and output of PST Email Containers'


def main(pst_file):
    """
    The main function opens a PST and calls functions to parse and report data from the PST
    :param pst_file: A string representing the path to the PST file to analyze
    :param report_name: Name of the report title (if supplied by the user)
    :return: None
    """
    opst = pypff.open(pst_file)
    root = opst.get_root_folder()

    message_data = folder_traverse(root, [], **{'pst_name': pst_file, 'folder_name': 'root'})

    header = ['pst_name', 'folder_name', 'creation_time', 'submit_time', 'delivery_time',
              'sender', 'subject', 'attachment_count']

    return message_data, header


def folder_traverse(base, message_data, pst_name, folder_name):
    """
    The folderTraverse function walks through the base of the folder and scans for sub-folders and messages
    :param base: Base folder to scan for new items within the folder.
    :param message_data: A list of data for output
    :param pst_name: A string representing the name of the pst file
    :param folder_name: A string representing the name of the folder
    :return: None
    """
    for folder in base.sub_folders:
        if folder.number_of_sub_folders:
            message_data = folder_traverse(folder, message_data, pst_name, folder.name)
        message_data = check_for_messages(folder, message_data, pst_name, folder.name)
    return message_data


def check_for_messages(folder, message_data, pst_name, folder_name):
    """
    The checkForMessages function reads folder messages if present and passes them to the report function
    :param folder: pypff.Folder object
    :param message_data: list to pass and extend with message info
    :param pst_name: A string representing the name of the pst file
    :param folder_name: A string representing the name of the folder
    :return: Dictionary of results by folder
    """
    for message in folder.sub_messages:
        message_dict = process_message(message)
        message_dict['pst_name'] = pst_name
        message_dict['folder_name'] = folder_name
        message_data.append(message_dict)
    return message_data


def process_message(message):
    """
    The processMessage function processes multi-field messages to simplify collection of information
    :param message: The pypff.Message object
    :return: A dictionary with message fields (values) and their data (keys)
    """
    return {
        "subject": message.subject,
        "sender": message.sender_name,
        "header": message.transport_headers,
        "body": message.plain_text_body,
        "creation_time": message.creation_time,
        "submit_time": message.client_submit_time,
        "delivery_time": message.delivery_time,
        "attachment_count": message.number_of_attachments,
    }
