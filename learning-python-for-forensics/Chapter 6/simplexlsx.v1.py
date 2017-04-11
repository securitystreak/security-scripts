import xlsxwriter
from datetime import datetime

school_data = [['Department', 'Students', 'Cumulative GPA', 'Final Date'],
               ['Computer Science', 235, 3.44, datetime(2015, 07, 23, 18, 00, 00)],
               ['Chemistry', 201, 3.26, datetime(2015, 07, 25, 9, 30, 00)],
               ['Forensics', 99, 3.8, datetime(2015, 07, 23, 9, 30, 00)],
               ['Astronomy', 115, 3.21, datetime(2015, 07, 19, 15, 30, 00)]]


def writeXLSX(data):
    workbook = xlsxwriter.Workbook('MyWorkbook.xlsx')
    main_sheet = workbook.add_worksheet('MySheet')

    date_format = workbook.add_format({'num_format': 'mm/dd/yy hh:mm:ss AM/PM'})

    for i, entry in enumerate(data):
        if i == 0:
            main_sheet.write(i, 0, entry[0])
            main_sheet.write(i, 1, entry[1])
            main_sheet.write(i, 2, entry[2])
            main_sheet.write(i, 3, entry[3])
        else:
            main_sheet.write(i, 0, entry[0])
            main_sheet.write_number(i, 1, entry[1])
            main_sheet.write_number(i, 2, entry[2])
            main_sheet.write_datetime(i, 3, entry[3], date_format)

    workbook.close()


writeXLSX(school_data)
