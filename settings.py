import pymysql as MySQLdb

database_host = 'localhost'
database_user = 'amlaccess'
database_password = '1a#L&IHOREGV'
database_name = 'aml'


#DO NOT MODIFY THE FOLLOWING OPTIONS AS THEY ARE ESSENTIAL FOR THE SOFTWARE'S OPERATION
def connection():
	conn = MySQLdb.connect(host=database_host, user = database_user, passwd = database_password, db = database_name)
	c = conn.cursor()
	return c, conn