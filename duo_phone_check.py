import csv
import sys
import duo_client

argv_iter = iter(sys.argv[1:])
def get_next_arg(prompt):
    try:
        return next(argv_iter)
    except StopIteration:
        return input(prompt)

admin_api = duo_client.Admin(
    ikey=get_next_arg('Admin API integration key: '),
    skey=get_next_arg('Admin API secret key: '),
    host=get_next_arg('Admin API hostname: '),
)

mode = get_next_arg('Type REMOVE to disassociate phones from users, otherwise type return to run in read only mode: ')

class duo_phone:
	def __init__(self, username, user_id, email, activated,capabilities,last_seen,model,number,phone_id,platform,phone_type):
		self.username = username
		self.user_id = user_id
		self.email = email
		self.activated = activated
		self.capabilities = capabilities
		self.last_seen = last_seen
		self.model = model
		self.number = number
		self.phone_id = phone_id
		self.platform = platform
		self.phone_type = phone_type


def getPhones():

	user_list = ['username1', 'username2', 'username3']

	phone_delete_list = []

	for user in user_list:

		try:
			u = admin_api.get_users_by_name(user)[0]
			phones = u['phones']
			for phone in phones:
				if not phone['activated']:
					p = duo_phone(u['username'], u['user_id'], u['email'], phone['activated'], phone['capabilities'], phone['last_seen'],phone['model'], phone['number'], phone['phone_id'], phone['platform'], phone['type'])
					phone_delete_list.append(p)

		except Exception as e:
			print('User "' + user + '" could not be found.')
			continue

		return phone_delete_list

def deletePhones(phone_delete_list):
	
	if phone_delete_list:
		for phone in phone_delete_list:
			admin_api.delete_user_phone(phone.user_id, phone.phone_id)
			print('Disassociate "' + phone.number + '" from ' + phone.username + '.')


def writeCSV(phone_delete_list, file_name="phone_delete_list.csv"):

    columns = []
    rows = []

    if phone_delete_list:
	    for phone in phone_delete_list:
	        
	        # build columns
	        for column in phone.__dict__.keys():
	            if column not in columns:
	                columns.append(column)

	        # build rows
	        row = ''
	        for column in columns:
	            if column in phone.__dict__.keys():
	                if phone.__dict__.get(column) is None:
	                    row += ','
	                else:
	                    row += str(phone.__dict__.get(column)) + ','
	            else:
	                row += ','
	        
	        row = row[:-1]
	        row += '\n'
	        rows.append(row)
	    
	    file = open(file_name, 'w')
	    
	    headers = ''

	    for column in columns:
	        headers += str(column) + ','
	    headers = headers[:-1]

	    file.write(headers + '\n')

	    line = ''

	    for row in rows:
	        file.write(row)

	    file.close()

def main():

	if mode == 'REMOVE':
		phone_delete_list = getPhones()
		writeCSV(phone_delete_list)
		deletePhones(phone_delete_list)
	else:
		print("Read-only Mode")
		phone_delete_list = getPhones()
		writeCSV(phone_delete_list)


if __name__ == "__main__":
    main()
