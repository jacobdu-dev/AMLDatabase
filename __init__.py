from flask import Flask, render_template, flash, request, url_for, redirect, session, jsonify, send_file, make_response
import sys
from FlaskApp.settings import *
from datetime import datetime
from passlib.hash import sha256_crypt
from pymysql.converters import escape_string as thwart
from io import BytesIO
import pytz
import gc


def convertbool(input):
    """
    Converts user form dropdown inputs into boolean values for mysql query or insert.
    'N/A' --> NULL; 'True' --> True; All other inputs are evaluated to False.
    Arguments:
    - input: String of user form input.
    Returns:
    - Boolean of evaluation.
    """
    if input == 'N/A':
        return None
    elif input == 'True':
        return True
    else:
        return False

def currdate():
    """
    Gets current date for mysql DATE input from the datetime library.
    Arguments: None
    Returns:
    - String of current date.
    """
    currentdate = datetime.now(pytz.timezone('America/Los_Angeles')).date()
    return currentdate.strftime('%Y-%m-%d')

def grabdata(table, condition = '*'):
    """
    Selects all rows from a table in the aml database based on input conditions.
    Arguments:
    - table: String of name of table in the aml database.
    - condition: String of sql query constraints. Defaulted to *. 
    Returns:
    - List of tuples of the rows from results of the query. 
    """
    if condition == '*':
        sqlarg = "SELECT * FROM " + table
    else:
        sqlarg = "SELECT * FROM " + table + " WHERE " + condition
    c, conn = connection()
    c.execute(sqlarg)
    dataset = []
    for row in c:
        dataset.append(row)
    c.close()
    conn.close()
    gc.collect()
    return sorted(dataset, reverse = True), sqlarg

def customquery(query):
    """
    Selects all rows from a table in the aml database based on input query.
    Arguments:
    - query: string of full sql query 
    Returns:
    - List of tuples of the rows from results of the query. 
    """
    sqlarg = query
    c, conn = connection()
    c.execute(sqlarg)
    dataset = []
    for row in c:
        dataset.append(row)
    c.close()
    conn.close()
    gc.collect()
    return sorted(dataset, reverse = True), sqlarg


app = Flask(__name__)
app.config.update(SECRET_KEY=SESSION_KEY)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000 #Max file transfer size is 16MB

booldict = {0: "False", 1: "True", None: "N/A"}

@app.route('/login/', methods=['GET','POST'])
def login():
    """
    Handles login requests.
    """
    error = request.args.get('error')
    message = request.args.get('message')
    try:
        if request.method == "POST":
            email = request.form['email']
            password = request.form['password']
            c, conn = connection()
            x = c.execute("SELECT * FROM users WHERE email = (%s)", [thwart(email)])
            if int(x) == 0:
                #if db query returned no rows (no email matches), reject login attempt
                error = "Login email does not exist in the system!"
                c.close()
                conn.close()
                gc.collect()
            else:
                tempdata = c.execute("SELECT * FROM users WHERE email = (%s)", [thwart(email)])
                fetchpass = c.fetchone()[4]
                if sha256_crypt.verify(password, fetchpass) is True:
                    #if a user is authenticated, retrieve userID, account activation status, and name.
                    session['logged_in'] = True
                    tempdata = c.execute("SELECT * FROM users WHERE email = (%s)", [thwart(email)])
                    session['uid'], session['active'], session['name'], session['email'] = c.fetchone()[0:4]
                    if not session['active']: 
                        # if an account is no longer active, automatically log out.
                        session.clear()
                        c.close()
                        conn.close()
                        gc.collect()
                        error = "Authenticated but account is no longer active. Please contact a current lab member to re-activate account."
                        return render_template("login.html", error = error, message = message)
                    c.close()
                    conn.close()
                    gc.collect()
                    return redirect(url_for('homepage'))
                else:
                    c.close()
                    conn.close()
                    gc.collect()
                    error = "Login information incorrect, please try again"
        return render_template("login.html", error = error, message = message)
    except Exception as e:
        error = 'An error has occured!'
        error = str(e)
        return render_template("login.html", error = error, message = message)


@app.route('/logout/')
def logout():
    """
    Handles logout requests.
    """
    error = request.args.get('error')
    message = request.args.get('message')
    session.clear()
    message = 'You are logged out!'
    return redirect(url_for('login', error = error, message = message))



@app.route('/add-user/', methods=['GET','POST'])
def adduser():
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    if not session['active']: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    try:
        if request.method == "POST":
            email = str(request.form['email'])
            if str(request.form['password']) != str(request.form['passwordver']): 
                #Entered passwords must match
                error = "Dicrepency between entered 'password' and 'verify password'."
                return render_template("addusers.html", error=error, message=message, name = session['name'], email = session['email'])
            password = sha256_crypt.encrypt(str(request.form['password']))
            name = str(request.form['name'])
            active = convertbool(str(request.form['active']))
            c, conn = connection()
            x = c.execute("SELECT * FROM users WHERE email = (%s)", [thwart(email)])
            if int(x) > 0:
                error = "Email already exists in the system."
                return render_template("addusers.html", error=error, message=message, name = session['name'], email = session['email'])
            else:
                c.execute(
                    "INSERT INTO users (active, name, email, password) VALUES (%s, %s, %s, %s)",
                    [active, thwart(name), thwart(email), thwart(password)])
                conn.commit()
                message = "User added successfully!"
                c.close()
                conn.close()
                gc.collect()
        return render_template("addusers.html", error=error, message=message, name = session['name'], email = session['email'])
    except Exception as e:
        error = str(e)
        return render_template("addusers.html", error=error, message=message, name = session['name'], email = session['email'])


@app.route('/view-users/')
def viewusers():
    """
    View all patients in AML database.
    1. Connect to AML Database
    2. Select all rows from AML.users table (no password).
    3. Return view users page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')


    c, conn = connection()
    c.execute("SELECT uid, active, name, email FROM users")
    userdata = []
    for row in c:
        userdata.append(row)
    c.close()
    conn.close()
    gc.collect()
    return render_template("viewusers.html", error = error, message = message, name = session['name'], email = session['email'], 
        userdata = userdata)



@app.route('/')
def homepage():
    """
    Default page. Unfinished
    """
    if 'active' not in session: return redirect(url_for('login', error = str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    return render_template("home.html", error = error, message = message, name = session['name'], email = session['email'])

@app.route('/add-patient/', methods=['GET','POST'])
def addpatient():
    """
    Add patient to AML database.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.patient table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    try:
        if request.method == "POST":
            ptid = int(request.form['ptid'])
            diagnosisDate = str(request.form['diagnosisdate'])
            amlType = str(request.form['amltype'])
            mll = convertbool(str(request.form['mllmut']))
            flt3Itd = convertbool(str(request.form['flt3idtmut']))
            flt3Kinase = convertbool(str(request.form['flt3kinasemut']))
            bcrAbl = convertbool(str(request.form['bcrablmut']))
            ptnotes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO patient (ptID, diagnosisDate, amlType, mll, flt3Itd, flt3Kinase, bcrAbl, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                [ptid, diagnosisDate, amlType, mll, flt3Itd, flt3Kinase, bcrAbl, ptnotes])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('viewpatients', message = "CIRM {} added to patients table successfully.".format(ptid)))
        return render_template("addpatient.html", error = error, message = message, name = session['name'], email = session['email'])
    except Exception as e:
        error = str(e)
        return render_template("addpatient.html", error = error, message = message, name = session['name'], email = session['email'])

@app.route('/view-patients/')
def viewpatients():
    """
    View all patients in AML database.
    1. Connect to AML Database
    2. Select all rows from AML.patient table.
    3. Return view patients page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    query = request.args.get('query')
    if query != None:
        #implement when search page is implemented.
        pass
    else:
        returned_data, sqlarg  = grabdata('patient')
    return render_template("viewpatients.html", error = error, message = message, name = session['name'], email = session['email'], 
        patients = returned_data, booldict = booldict, sqlquery = sqlarg)


@app.route('/patient/')
def patient():
    """
    View specific patient from AML database.
    1. Connect to AML Database
    2. Get rows related to patient based on ptid argument: patient, mutations, treatment history, sample log, vial usage log.
    3. Return view patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    if ptid == None:
        return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    else:
        pt_data, arg = grabdata('patient',"ptID = '{}'".format(ptid))
        mut_data, arg = grabdata('ngsMutations',"ptID = '{}'".format(ptid))
        treat_hist, arg = grabdata('treatments',"ptID = '{}'".format(ptid))
        bm_sample_log, arg = grabdata('bmCollection',"ptID = '{}'".format(ptid))

        #pb_sample_log, arg = grabdata('nsgMutations',"ptID = '{}'".format(ptid))
        vialLogQuery = """
        SELECT vialLog.entryID, vialLog.vialsTaken, vialLog.sampleType, vialLog.sampleID, users.name, vialLog.expr, vialLog.date
        FROM vialLog 
        LEFT JOIN users
        ON vialLog.uID = users.uid
        WHERE vialLog.ptID = {}
        """.format(ptid)
        vial_usage_log, arg = customquery(vialLogQuery)
    return render_template("patient.html", error = error, message = message, name = session['name'], email = session['email'], ptID = ptid, 
        pt_data = pt_data, booldict = booldict, mut_data=mut_data, bm_sample_log=bm_sample_log, pb_sample_log=[], treat_hist=treat_hist, vial_usage_log=vial_usage_log)




@app.route('/add-mutation/', methods=['GET','POST'])
def addmutation():
    """
    Add mutation to patient.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.ngsMutations table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    try:
        if request.method == "POST":
            gene = str(request.form['gene'])
            mutation = str(request.form['mutation'])
            vaf = float(request.form['vaf'])
            tier = int(request.form['tier'])
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO ngsMutations (ptID, gene, mutation, vaf, tier, notes) VALUES (%s, %s, %s, %s, %s, %s)",
                [ptid, gene, mutation, vaf, tier, notes])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('patient', ptid = ptid,message = "Mutation added successfully."))
        return render_template("addmutation.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid)
    except Exception as e:
        error = str(e)
        return render_template("addmutation.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid)


@app.route('/add-treatment/', methods=['GET','POST'])
def addtreatment():
    """
    Add treatment to patient.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.treatments table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    try:
        if request.method == "POST":
            drug = str(request.form['drug'])
            startdate = str(request.form['startdate'])
            enddate = str(request.form['enddate'])
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO treatments (ptID, drug, startDate, endDate, notes) VALUES (%s, %s, %s, %s, %s)",
                [ptid, drug, startdate, enddate, notes])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('patient', ptid = ptid,message = "Treatment added successfully."))
        return render_template("addtreatment.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid)
    except Exception as e:
        error = str(e)
        return render_template("addtreatment.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid)



@app.route('/add-bm-collection/', methods=['GET','POST'])
def addbmsample():
    """
    Add patient to AML database.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.patient table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    try:
        if request.method == "POST":
            doc = str(request.form['doc'])
            dop = str(request.form['dop'])
            vials = int(request.form['vials'])
            cellNumbers = int(request.form['cellNumbers'])
            stype = int(request.form['stype'])
            postTransplant = bool(request.form['postTransplant'])
            blast = float(request.form['blast'])
            freezedownMedia = str(request.form['freezedownMedia'])
            location = str(request.form['location'])
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO bmCollection (ptID, doc, dop, vials, cellNumbers, type, postTransplant, blast, freezedownMedia, location, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [ptid, doc, dop, vials, cellNumbers, stype, postTransplant, blast, freezedownMedia, location, notes])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('patient', ptid = ptid, message = "BM Collection added successfully."))
        return render_template("addbmsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate())
    except Exception as e:
        error = str(e)
        return render_template("addbmsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate())



@app.route('/bm-collection/', methods=['GET','POST'])
def bmsample():
    """
    Add patient to AML database.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.patient table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    bmid = request.args.get('bmid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    if bmid == None: return redirect(url_for('patient', ptid = ptid, error = "No BM ID specified. Redirected to view CIRM {}.".format(ptid)))
    try:
        if request.method == "POST":
            doc = str(request.form['doc'])
            dop = str(request.form['dop'])
            vials = int(request.form['vials'])
            cellNumbers = int(request.form['cellNumbers'])
            stype = int(request.form['stype'])
            postTransplant = bool(request.form['postTransplant'])
            blast = float(request.form['blast'])
            freezedownMedia = str(request.form['freezedownMedia'])
            location = str(request.form['location'])
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                """UPDATE bmCollection SET doc = %s, dop = %s, vials = %s, cellNumbers = %s, type = %s, postTransplant = %s, blast = %s
                , freezedownMedia = %s, location = %s, notes = %s WHERE bmID =  %s AND ptID = %s""",
                [doc, dop, vials, cellNumbers, stype, postTransplant, blast, freezedownMedia, location, notes, bmid, ptid])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('patient', ptid = ptid, message = "BM Collection added successfully."))
        #Check whether a BM sample exists
        bm_sample, arg = grabdata('bmCollection',"ptID = '{}' AND bmID = '{}'".format(ptid, bmid))
        if len(bm_sample) == 0: return redirect(url_for('patient', ptid = ptid, error = "Specified BM ID does not exist for this patient. Redirected to view CIRM {}.".format(ptid)))

        return render_template("bmsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate(), bm_sample = bm_sample)
    except Exception as e:
        error = str(e)
        return render_template("bmsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate())




@app.route('/take-vial/', methods=['GET','POST'])
def takevial():
    """
    Add mutation to patient.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.ngsMutations table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    sampleType = request.args.get('sampletype')
    sampleID = request.args.get('sampleid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    if sampleType not in [0, 1, '0', '1']: return redirect(url_for('patient', error = "Invalid sample type. Redirected to view CIRM {}".format(ptid), ptid=ptid))
    #should check valid pb/bm ID but it should not be possible to get to this page with an invalid sample ID unless the URL was altered by the user
    try:
        if request.method == "POST":
            vialsTaken = int(request.form['vialsTaken'])
            expr = str(request.form['expr'])
            c, conn = connection()
            x = c.execute("SELECT TAKE_VIAL(%s, %s, %s, %s, %s, %s)", [ptid, session['uid'], vialsTaken, sampleType, sampleID, expr])
            conn.commit()
            returned_code = c.fetchone()
            c.close()
            conn.close()
            gc.collect()
            if returned_code[0] == 0:
                message = "Vial usage logged"
            else:
                error = "Error: Invalid sampleID, sampleType, or vials used is greater than vials remaining. Vial usage was NOT logged."
            return redirect(url_for('patient', ptid = ptid, message = message, error = error))
        return render_template("takevial.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, sampleType = sampleType, sampleID = sampleID)
    except Exception as e:
        error = str(e)
        return render_template("takevial.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, sampleType = sampleType, sampleID = sampleID)


@app.route('/add-attachment/', methods=['GET','POST'])
def addattachment():
    """
    Add patient to AML database.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.patient table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    try:
        if request.method == "POST":
            file = request.files['attachment']
            filename = file.filename
            data = file.read()
            description = str(request.form['description'])
            if filename == '':
                #Empty files are a waste of resources
                error = "No file selected"
                render_template("addattachment.html", error = error, message = message, name = session['name'], email = session['email']
                    , ptID = ptid)
            c, conn = connection()
            c.execute(
                "INSERT INTO files (ptID, uID, filename, data, description) VALUES (%s, %s, %s, %s, %s)",
                [ptid, session['uid'], filename, data, description])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('patient', ptid = ptid, message = "Attachment added successfully."))
        return render_template("addattachment.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid)
    except Exception as e:
        error = str(e)
        return render_template("addattachment.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid)

@app.route('/get-file/')
def getfile():
    """
    Add patient to AML database.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.patient table and commit changes.
    2. Else, Return add patient page.
    """
    if 'active' not in session: return redirect(url_for('login', error=str('Restricted area! Please log in!')))
    error = request.args.get('error')
    message = request.args.get('message')
    fileid = request.args.get('fileid')
    if fileid == None: return redirect(url_for('viewpatients', error = "No file ID specified. Redirected to view all patients."))
    attachment_data, arg = grabdata('files', 'fileID = {}'.format(fileid))
    if len(attachment_data) == 0: return redirect(url_for('viewpatients', error = "File ID does not exist. Redirected to view all patients."))
    return send_file(BytesIO(attachment_data[0][4]), download_name = attachment_data[0][3], as_attachment = True)

if __name__ == "__main__":
    app.run()
