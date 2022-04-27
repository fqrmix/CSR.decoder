import PySimpleGUI as sg
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM


def convert(data):
    if isinstance(data, bytes):
        return data.decode('ascii')

    if isinstance(data, dict):
        return dict(map(convert, data.items()))

    if isinstance(data, tuple):
        return map(convert, data)

    return data


def CSRcheck(path):
    with open(path, 'r') as csr_file:
        file_begin = csr_file.readline()
        file_end = csr_file.readlines()[-1]
        if path.endswith('.csr'):
            if (file_begin.strip() == "-----BEGIN CERTIFICATE REQUEST-----") \
                    and (file_end.strip() == "-----END CERTIFICATE REQUEST-----"):
                return True
            else:
                return False


layout = [  # Layout
    [sg.Text('CSR'), sg.InputText(), sg.FileBrowse(key="-IN-")],
    [sg.Output(size=(88, 20))],
    [sg.Submit(), sg.Cancel()]
]
window = sg.Window('CSR decode', layout)

while True:  # The Event Loop
    event, values = window.read()
    if event in (None, 'Exit', 'Cancel'):
        break
    if event == 'Submit':
        filePath = values["-IN-"]
        if CSRcheck(filePath):
            try:
                csr = open(filePath, 'r').read()
            except FileNotFoundError:
                print("File {} does not exist".format(filePath))

            req = load_certificate_request(FILETYPE_PEM, csr)
            key = req.get_pubkey()
            key_type = 'RSA' if key.type() == OpenSSL.crypto.TYPE_RSA else 'DSA'
            subject = req.get_subject()
            components = dict(subject.get_components())
            str_components = convert(components)
            print("Common name:", str_components['CN'])
            print("Organisation:", str_components['O'])
            print("Organisation unit", str_components['OU'])
            print("City/locality:", str_components['L'])
            print("State/province:", str_components['ST'])
            print("Country:", str_components['C'])
            print("Signature algorithm:", '?')
            print("Key algorithm:", key_type)
            print("Key size:", key.bits())
        else:
            print('Invalid CSR file!')
# Close the window i.e. release resource
window.close()
