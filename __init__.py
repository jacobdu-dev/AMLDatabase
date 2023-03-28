from flask import Flask, render_template, flash, request, url_for, redirect, session, jsonify, send_file, make_response
import sys
from Settings.settings import *
from datetime import datetime
from passlib.hash import sha256_crypt
from pymysql.converters import escape_string as thwart
from flask_sslify import SSLify
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
sslify = SSLify(app)
addusermode = False

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
    if not addusermode:
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
                if addusermode: return render_template("addusers.html", error=error, message=message)
                return render_template("addusers.html", error=error, message=message, name = session['name'], email = session['email'])
            password = sha256_crypt.encrypt(str(request.form['password']))
            name = str(request.form['name'])
            active = convertbool(str(request.form['active']))
            c, conn = connection()
            x = c.execute("SELECT * FROM users WHERE email = (%s)", [thwart(email)])
            if int(x) > 0:
                error = "Email already exists in the system."
                if addusermode: return render_template("addusers.html", error=error, message=message)
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
        if addusermode: return render_template("addusers.html", error=error, message=message)
        return render_template("addusers.html", error=error, message=message, name = session['name'], email = session['email'])
    except Exception as e:
        error = str(e)
        if addusermode: return render_template("addusers.html", error=error, message=message)
        return render_template("addusers.html", error=error, message=message, name = session['name'], email = session['email'])




@app.route('/edit-user/', methods=['GET','POST'])
def edituser():
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
    uid = request.args.get('uid')
    if uid == None: uid = session['uid']
    try:
        if request.method == "POST":
            #Handle BM sample entry update
            name = str(request.form['name'])
            email = str(request.form['email'])
            active = int(request.form['active'])
            c, conn = connection()
            c.execute(
                """UPDATE users SET name = %s, email = %s, active = %s WHERE uid =  %s""",
                [name, email, active, uid])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            message = "Account updated successfully."
            if request.form['password'] != '':
                #Verify first and second password match
                if request.form['password'] != request.form['passwordver']: 
                    message = "Verify password entered does not match the first password. Password failed to update."
                else:
                    #Perform user password verification check
                    c, conn = connection()
                    tempdata = c.execute("SELECT * FROM users WHERE uid = (%s)", [session['uid']])
                    fetchpass = c.fetchone()[4]
                    conn.commit()
                    c.close()
                    conn.close()
                    gc.collect()
                    if sha256_crypt.verify(request.form['currpassword'], fetchpass) is True:
                        c, conn = connection()
                        c.execute(
                            """UPDATE users SET password = %s WHERE uid =  %s""",
                            [thwart(sha256_crypt.encrypt(str(request.form['password']))), uid])
                        conn.commit()
                        c.close()
                        conn.close()
                        gc.collect()
                        message = "Password and account updated successfully."
        #Check user exists
        user_data, arg = customquery("SELECT uid, name, email, active FROM users WHERE uid = {}".format(uid))
        if len(user_data) == 0: return redirect(url_for('viewusers',error = "Specified user ID does not exist. Redirected to view all users."))
        return render_template("edituser.html", error = error, message = message, name = session['name'], email = session['email']
            , user_data = user_data)
    except Exception as e:
        error = str(e)
        return render_template("edituser.html", error = error, message = message, name = session['name'], email = session['email']
            , user_data = [])




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
            ptid = request.form['ptid']
            diagnosisDate = str(request.form['diagnosisdate'])
            amlType = str(request.form['amltype'])
            mll = convertbool(str(request.form['mllmut']))
            flt3Itd = convertbool(str(request.form['flt3idtmut']))
            flt3Kinase = convertbool(str(request.form['flt3kinasemut']))
            bcrAbl = convertbool(str(request.form['bcrablmut']))
            ptnotes = str(request.form['notes'])
            c, conn = connection()
            if request.form['ptid'] == '':
                c.execute(
                    "INSERT INTO patient (diagnosisDate, amlType, mll, flt3Itd, flt3Kinase, bcrAbl, notes) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    [diagnosisDate, amlType, mll, flt3Itd, flt3Kinase, bcrAbl, ptnotes])
            else:
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
    query = """
    SELECT patient.ptID, patient.diagnosisDate, patient.amlType, patient.mll, patient.flt3Itd, patient.flt3Kinase,
    patient.bcrAbl, patient.notes, mut.mutgenes, bmd.count AS bmd_count, bmrm.count AS bmrm_count, bmrl.count AS bmrl_count
    , pbd.count AS pbd_count, pbrm.count AS pbrm_count, pbrl.count AS pbrl_count
    FROM patient 
    LEFT JOIN (
        SELECT ptID, GROUP_CONCAT(gene) AS mutgenes FROM ngsMutations GROUP BY ptID
        ) mut 
    ON patient.ptID = mut.ptID 
    LEFT JOIN (
        SELECT ptID, SUM(vials) AS count FROM bmCollection WHERE type = 0 GROUP BY ptID
        ) bmd
    ON patient.ptID = bmd.ptID 
    LEFT JOIN (
        SELECT ptID, SUM(vials) AS count FROM bmCollection WHERE type = 1 GROUP BY ptID
        ) bmrm
    ON patient.ptID = bmrm.ptID
    LEFT JOIN (
        SELECT ptID, SUM(vials) AS count FROM bmCollection WHERE type = 2 GROUP BY ptID
        ) bmrl
    ON patient.ptID = bmrl.ptID
    LEFT JOIN (
        SELECT ptID, SUM(vials) AS count FROM pbCollection WHERE type = 0 GROUP BY ptID
        ) pbd
    ON patient.ptID = pbd.ptID 
    LEFT JOIN (
        SELECT ptID, SUM(vials) AS count FROM pbCollection WHERE type = 1 GROUP BY ptID
        ) pbrm
    ON patient.ptID = pbrm.ptID
    LEFT JOIN (
        SELECT ptID, SUM(vials) AS count FROM pbCollection WHERE type = 2 GROUP BY ptID
        ) pbrl
    ON patient.ptID = pbrl.ptID;
    """

    if query != None:
        returned_data, sqlarg  = customquery(query)
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
        pb_sample_log, arg = grabdata('pbCollection',"ptID = '{}'".format(ptid))
        vialLogQuery = """
        SELECT vialLog.entryID, vialLog.vialsTaken, vialLog.sampleType, vialLog.sampleID, users.name, vialLog.expr, vialLog.date
        FROM vialLog 
        LEFT JOIN users
        ON vialLog.uID = users.uid
        WHERE vialLog.ptID = {}
        """.format(ptid)
        vial_usage_log, arg = customquery(vialLogQuery)
        attachmentsQuery = """
        SELECT files.fileid, users.name, files.filename, files.date, files.description
        FROM files 
        LEFT JOIN users
        ON files.uID = users.uid
        WHERE files.ptID = {}
        """.format(ptid)
        attachments_log, arg = customquery(attachmentsQuery)
    return render_template("patient.html", error = error, message = message, name = session['name'], email = session['email'], ptID = ptid, 
        pt_data = pt_data, booldict = booldict, mut_data=mut_data, bm_sample_log=bm_sample_log, pb_sample_log = pb_sample_log, treat_hist=treat_hist, 
        vial_usage_log=vial_usage_log, attachments_log = attachments_log)




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
            postTransplant = int(request.form['postTransplant'])
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
            #Handle BM sample entry update
            doc = str(request.form['doc'])
            dop = str(request.form['dop'])
            vials = int(request.form['vials'])
            cellNumbers = int(request.form['cellNumbers'])
            stype = int(request.form['stype'])
            postTransplant = int(request.form['postTransplant'])
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
            #Handle Clinical Flow Entry if one exists
            if 'flowBlast' in request.form:
                clinicalFlowID = request.form['clinicalFlowID']
                flowBlast = request.form['flowBlast']
                flowDoc = request.form['flowDoc']
                cd4 = request.form['cd4']
                cd34 = request.form['cd34']
                cd64 = request.form['cd64']
                cd117 = request.form['cd117']
                hlaDR = request.form['hlaDR']
                lymphoid = request.form['lymphoid']
                tCells = request.form['tCells']
                bCells = request.form['bCells']
                nkCells = request.form['nkCells']
                flowNotes = str(request.form['flowNotes'])
                c, conn = connection()
                c.execute(
                    """UPDATE clinicalFlow SET doc = %s, blasts = %s, cd4 = %s, cd34 = %s, cd64 = %s, cd117 = %s, hlaDR = %s
                    , lymphoid = %s, tCells = %s, bCells = %s, nkCells = %s, notes = %s WHERE clincalFlowID =  %s AND ptID = %s""",
                    [flowDoc, flowBlast, cd4, cd34, cd64, cd117, hlaDR, lymphoid, tCells, bCells, nkCells, notes, clinicalFlowID, ptid])
                conn.commit()
                c.close()
                conn.close()
                gc.collect()
            return redirect(url_for('patient', ptid = ptid, message = "Records updated."))
        #Check whether a BM sample exists
        bm_sample, arg = grabdata('bmCollection',"ptID = '{}' AND bmID = '{}'".format(ptid, bmid))
        if len(bm_sample) == 0: return redirect(url_for('patient', ptid = ptid, error = "Specified BM ID does not exist for this patient. Redirected to view CIRM {}.".format(ptid)))
        #Clinical Flow entry check
        if bm_sample[0][11] != None: 
            clinicalFlow_data, arg = grabdata('clinicalFlow',"ptID = '{}' AND clincalFlowID = '{}'".format(ptid, bm_sample[0][11]))
        else:
            clinicalFlow_data = []
        return render_template("bmsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate(), bm_sample = bm_sample, clinicalFlow_data = clinicalFlow_data)
    except Exception as e:
        error = str(e)
        return render_template("bmsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate(), bm_sample = [], clinicalFlow_data = [])


@app.route('/add-clinical-flow/', methods=['GET','POST'])
def addclinicalflow():
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
            blast = float(request.form['blast'])
            cd4 = request.form['cd4']
            cd34 = request.form['cd34']
            cd64 = request.form['cd64']
            cd117 = request.form['cd117']
            hlaDR = request.form['hlaDR']
            lymphoid = request.form['lymphoid']
            tCells = request.form['tCells']
            bCells = request.form['bCells']
            nkCells = request.form['nkCells']
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO clinicalFlow (ptID, doc, blasts, cd4, cd34, cd64, cd117, hlaDR, lymphoid, tCells, bCells, nkCells, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [ptid, doc, blast, cd4, cd34, cd64, cd117, hlaDR, lymphoid, tCells, bCells, nkCells, notes])
            conn.commit()
            clincalFlowID = cbcID = c.lastrowid
            c.close()
            conn.close()
            gc.collect()
            #update clinical flow field of BM collection
            c, conn = connection()
            c.execute(
                """UPDATE bmCollection SET clincalFlowID = %s WHERE bmID =  %s AND ptID = %s""", [clincalFlowID, bmid, ptid])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('bmsample', ptid = ptid, bmid = bmid, message = "Clinical flow added successfully."))
        return render_template("addclinicalflow.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, bmID = bmid, currdate = currdate())
    except Exception as e:
        error = str(e)
        return render_template("addclinicalflow.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, bmID = bmid, currdate = currdate())


@app.route('/add-pb-collection/', methods=['GET','POST'])
def addpbsample():
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
            lp = int(request.form['lp'])
            stype = int(request.form['stype'])
            postTransplant = int(request.form['postTransplant'])
            blast = request.form['blast']
            freezedownMedia = str(request.form['freezedownMedia'])
            location = str(request.form['location'])
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO pbCollection (ptID, doc, dop, vials, cellNumbers, lp, type, postTransplant, blast, freezedownMedia, location, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [ptid, doc, dop, vials, cellNumbers, lp, stype, postTransplant, blast, freezedownMedia, location, notes])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('patient', ptid = ptid, message = "PB Collection added successfully."))
        return render_template("addpbsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate())
    except Exception as e:
        error = str(e)
        return render_template("addpbsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate())



@app.route('/pb-collection/', methods=['GET','POST'])
def pbsample():
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
    pbid = request.args.get('pbid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    if pbid == None: return redirect(url_for('patient', ptid = ptid, error = "No PB ID specified. Redirected to view CIRM {}.".format(pbid)))
    try:
        if request.method == "POST":
            #Handle PB sample entry update
            doc = str(request.form['doc'])
            dop = str(request.form['dop'])
            vials = int(request.form['vials'])
            cellNumbers = int(request.form['cellNumbers'])
            lp = int(request.form['lp'])
            stype = int(request.form['stype'])
            postTransplant = int(request.form['postTransplant'])
            blast = float(request.form['blast'])
            freezedownMedia = str(request.form['freezedownMedia'])
            location = str(request.form['location'])
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                """UPDATE pbCollection SET doc = %s, dop = %s, vials = %s, cellNumbers = %s, lp = %s, type = %s, postTransplant = %s, blast = %s
                , freezedownMedia = %s, location = %s, notes = %s WHERE pbID =  %s AND ptID = %s""",
                [doc, dop, vials, cellNumbers, lp, stype, postTransplant, blast, freezedownMedia, location, notes, pbid, ptid])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            #Handle Clinical CBC Entry if one exists
            if 'cbcID' in request.form:
                cbcID = request.form['cbcID']
                cbcBlast = request.form['cbcBlast']
                cbcDoc = request.form['cbcDoc']
                wbc = request.form['wbc']
                rbc = request.form['rbc']
                platlets = request.form['platlets']
                neutrophils = request.form['neutrophils']
                lymphocytes = request.form['lymphocytes']
                eosinophils = request.form['eosinophils']
                basophils = request.form['basophils']
                monocytes = request.form['monocytes']
                cbcNotes = str(request.form['cbcNotes'])
                c, conn = connection()
                c.execute(
                    """UPDATE cbc SET doc = %s, wbc = %s, rbc = %s, blasts = %s, platlets = %s, neutrophils = %s
                    , lymphocytes = %s, monocytes = %s, eosinophils = %s, basophils = %s, notes = %s WHERE cbcID =  %s AND ptID = %s""",
                    [cbcDoc, cbcBlast, wbc, rbc, platlets, neutrophils, lymphocytes, eosinophils, basophils, monocytes, cbcNotes, cbcID, ptid])
                conn.commit()
                c.close()
                conn.close()
                gc.collect()
            return redirect(url_for('patient', ptid = ptid, message = "Records updated."))
        #Check whether a PB sample exists
        pb_sample, arg = grabdata('pbCollection',"ptID = '{}' AND pbID = '{}'".format(ptid, pbid))
        if len(pb_sample) == 0: return redirect(url_for('patient', ptid = ptid, error = "Specified PB ID does not exist for this patient. Redirected to view CIRM {}.".format(ptid)))
        #Clinical CBC entry check
        if pb_sample[0][12] != None: 
            cbc_data, arg = grabdata('cbc',"ptID = '{}' AND cbcID = '{}'".format(ptid, pb_sample[0][12]))
        else:
            cbc_data = []
        return render_template("pbsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate(), pb_sample = pb_sample, cbc_data = cbc_data)
    except Exception as e:
        error = str(e)
        return render_template("pbsample.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, currdate = currdate(), pb_sample = [], cbc_data = [])




@app.route('/add-cbc/', methods=['GET','POST'])
def addcbc():
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
    pbid = request.args.get('pbid')
    if ptid == None: return redirect(url_for('viewpatients', error = "No patient ID specified. Redirected to view all patients."))
    if pbid == None: return redirect(url_for('patient', ptid = ptid, error = "No PB ID specified. Redirected to view CIRM {}.".format(ptid)))
    try:
        if request.method == "POST":
            doc = str(request.form['doc'])
            wbc = request.form['wbc']
            rbc = request.form['rbc']
            platlets = request.form['platlets']
            neutrophils = request.form['neutrophils']
            lymphocytes = request.form['lymphocytes']
            eosinophils = request.form['eosinophils']
            basophils = request.form['basophils']
            cbcBlast = request.form['cbcBlast']
            monocytes = request.form['monocytes']
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO cbc (ptID, doc, wbc, rbc, blasts, platlets, neutrophils, lymphocytes, monocytes, eosinophils, basophils, notes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [ptid, doc, wbc, rbc, cbcBlast, platlets, neutrophils, lymphocytes, eosinophils, basophils, monocytes, notes])
            conn.commit()
            cbcID = c.lastrowid
            c.close()
            conn.close()
            gc.collect()
            #update  cbc field of PB collection
            c, conn = connection()
            c.execute(
                """UPDATE pbCollection SET cbcID = %s WHERE pbID =  %s AND ptID = %s""", [cbcID,pbid, ptid])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('pbsample', ptid = ptid, pbid = pbid, message = "CBC added successfully."))
        return render_template("addcbc.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, pbID = pbid, currdate = currdate())
    except Exception as e:
        error = str(e)
        return render_template("addcbc.html", error = error, message = message, name = session['name'], email = session['email']
            , ptID = ptid, pbID = pbid, currdate = currdate())



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
