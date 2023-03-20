from flask import Flask, render_template, flash, request, url_for, redirect, session, jsonify, send_file, make_response
import sys
from FlaskApp.settings import *
from datetime import datetime
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

app = Flask(__name__)

booldict = {0: "False", 1: "True", None: "N/A"}

@app.route('/')
def homepage():
    """
    Default page. Unfinished
    """
    error = request.args.get('error')
    message = request.args.get('message')
    return render_template("home.html", error = error, message = message)

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
        return render_template("addpatient.html", error = error, message = message)
    except Exception as e:
        error = str(e)
        return render_template("addpatient.html", error = error, message = message)
    return render_template("addpatient.html")

@app.route('/view-patients/')
def viewpatients():
    """
    View all patients in AML database.
    1. Connect to AML Database
    2. Select all rows from AML.patient table.
    3. Return view patients page.
    """
    error = request.args.get('error')
    message = request.args.get('message')
    query = request.args.get('query')
    if query != None:
        #implement when search page is implemented.
        pass
    else:
        returned_data, sqlarg  = grabdata('patient')
    return render_template("viewpatients.html", error = error, message = message, patients = returned_data, booldict = booldict, sqlquery = sqlarg)


@app.route('/patient/')
def patient():
    """
    View specific patient from AML database.
    1. Connect to AML Database
    2. Get rows related to patient based on ptid argument: patient, mutations, treatment history, sample log, vial usage log.
    3. Return view patient page.
    """
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    if ptid == None:
        return redirect(url_for('viewpatients'), error = "No patient ID specified. Redirected to view all patients.")
    else:
        pt_data, arg = grabdata('patient',"ptID = '{}'".format(ptid))
        mut_data, arg = grabdata('nsgMutations',"ptID = '{}'".format(ptid))
        #treat_hist, arg = grabdata('treatments',"ptID = '{}'".format(ptid))
        #bm_sample_log, arg = grabdata('nsgMutations',"ptID = '{}'".format(ptid))
        #pb_sample_log, arg = grabdata('nsgMutations',"ptID = '{}'".format(ptid))
        #cbc_log, arg = grabdata('nsgMutations',"ptID = '{}'".format(ptid))
        #clin_flow_log, arg = grabdata('nsgMutations',"ptID = '{}'".format(ptid))
        #vial_usage_log, arg = grabdata('nsgMutations',"ptID = '{}'".format(ptid))
    return render_template("patient.html", error = error, message = message, ptID = ptid, pt_data = pt_data, booldict = booldict, mut_data=mut_data, bm_sample_log=[], pb_sample_log=[], treat_hist=[], vial_usage_log=[])




@app.route('/add-mutation/', methods=['GET','POST'])
def addmutation():
    """
    Add patient to AML database.
    1. Check if current request is a submission request.
        if True, get all entries from the submission form and convert to proper datatype for MySQL insert.
        Connect to AML MySQL database.
        Insert entry as new row into AML.patient table and commit changes.
    2. Else, Return add patient page.
    """
    error = request.args.get('error')
    message = request.args.get('message')
    ptid = request.args.get('ptid')
    if ptid == None: return redirect(url_for('viewpatients'), error = "No patient ID specified. Redirected to view all patients.")
    try:
        if request.method == "POST":
            gene = str(request.form['gene'])
            mutation = str(request.form['mutation'])
            vaf = float(request.form['vaf'])
            notes = str(request.form['notes'])
            c, conn = connection()
            c.execute(
                "INSERT INTO nsgMutations (ptID, gene, mutation, vaf, notes) VALUES (%s, %s, %s, %s, %s)",
                [ptid, gene, mutation, vaf, notes])
            conn.commit()
            c.close()
            conn.close()
            gc.collect()
            return redirect(url_for('patient', ptid = ptid,message = "Mutation added successfully.".format(ptid)))
        return render_template("addmutation.html", error = error, message = message, ptID = ptid)
    except Exception as e:
        error = str(e)
        return render_template("addmutation.html", error = error, message = message)
    return render_template("addmutation.html")

if __name__ == "__main__":
    app.run()
