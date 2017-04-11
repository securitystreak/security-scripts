import xlsxwriter

__author__ = 'Preston Miller & Chapin Bryce'
__date__ = '20160401'
__version__ = 0.04
__description__ = 'Write XSLX file.'

ALPHABET = [chr(i) for i in range(ord('A'), ord('Z') + 1)]


def writer(output, headers, output_data, **kwargs):
    """
    The writer function writes excel output for the framework
    :param output: the output filename for the excel spreadsheet
    :param headers: the name of the spreadsheet columns
    :param output_data: the data to be written to the excel spreadsheet
    :return: Nothing
    """
    wb = xlsxwriter.Workbook(output)
    
    if headers is None:
        print '[-] Received empty headers... \n[-] Skipping writing output.'
        return

    if len(headers) <= 26:
        title_length = ALPHABET[len(headers) - 1]
    else:
        title_length = 'Z'

    ws = addWorksheet(wb, title_length)

    if 'recursion' in kwargs.keys():
        for i, data in enumerate(output_data):
            if i > 0:
                ws = addWorksheet(wb, title_length)
            cell_length = len(data)
            tmp = []
            for dictionary in data:
                tmp.append(
                    [unicode(dictionary[x]) if x in dictionary.keys() else '' for x in headers]
                )

            ws.add_table('A3:' + title_length + str(3 + cell_length),
                         {'data': tmp, 'columns': [{'header': x} for x in headers]})

    else:
        cell_length = len(output_data)
        tmp = []
        for data in output_data:
            tmp.append([unicode(data[x]) if x in data.keys() else '' for x in headers])
        ws.add_table('A3:' + title_length + str(3 + cell_length),
                     {'data': tmp, 'columns': [{'header': x} for x in headers]})

    wb.close()


def addWorksheet(wb, length, name=None):
    """
    The addWorksheet function creates a new formatted worksheet in the workbook
    :param wb: The workbook object
    :param length: The range of rows to merge
    :param name: The name of the worksheet
    :return: ws, the worksheet
    """
    title_format = wb.add_format({'bold': True, 'font_color': 'black',
                                  'bg_color': 'white', 'font_size': 30,
                                  'font_name': 'Arial', 'align': 'center'})
    ws = wb.add_worksheet(name)

    ws.merge_range('A1:' + length + '1', 'XYZ Corp', title_format)
    ws.merge_range('A2:' + length + '2', 'Case ####', title_format)
    return ws