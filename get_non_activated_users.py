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

class duo_user:
	def __init__(self,username, user_id, user_phones_activated_count=0, user_phones_count=0, phone1=None, phone2=None, phone3=None, phone4=None):
		self.username=username
		self.user_id=user_id
		self.user_phones_activated_count=user_phones_activated_count
		self.user_phones_count=user_phones_count
		self.phone1=phone1
		self.phone2=phone2
		self.phone3=phone3
		self.phone4=phone4

def getUsers():

	user_list = []

	try:
		users = admin_api.get_users_iterator()

		for user in users:

			phone1 = None
			phone2 = None
			phone3 = None
			phone4 = None

			user_phones = user['phones']

			user_phones_count=0
			user_phones_activated_count=0

			for i, phone in enumerate(user_phones):

				user_phones_count+=1
				if phone['activated']:
					user_phones_activated_count+=1

				if i == 0:
					phone1 = '"' + str(phone) + '"'
				if i == 1:
					phone2 = '"' + str(phone) + '"'
				if i == 2:
					phone3 = '"' + str(phone) + '"'
				if i == 3:
					phone4 = '"' + str(phone) + '"'

			if user_phones_activated_count==0:
				user_list.append(duo_user(user['username'],user['user_id'],user_phones_activated_count,user_phones_count,phone1,phone2,phone3,phone4))
	
	except Exception as e:

		print(str(e))

	return user_list


def writeCSV(user_list, file_name="user_list.csv"):

    columns = []
    rows = []

    if user_list:
	    for user in user_list:
	        
	        # build columns
	        for column in user.__dict__.keys():
	            if column not in columns:
	                columns.append(column)

	        # build rows
	        row = ''
	        for column in columns:
	            if column in user.__dict__.keys():
	                if user.__dict__.get(column) is None:
	                    row += ','
	                else:
	                    row += str(user.__dict__.get(column)) + ','
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

	writeCSV(getUsers())


if __name__ == "__main__":
    main()
