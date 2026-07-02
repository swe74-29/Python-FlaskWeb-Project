from flask import Flask, render_template
app = Flask(__name__)
@app.route("/")
def home_page():
    return render_template('index.html')
@app.route('/DOCS')
def DOCS():
   return 'NOT MADE YET!'
@app.route('/GITHUB')
def GITHUB():
   return 'NOT MADE YET!'
@app.route('/ABOUT')
def ABOUT():
   return 'NOT MADE YET!'
@app.route('/MIT_License')
def MIT_License():
   return 'NOT MADE YET!'
@app.route('/Source_Code')
def Source_Code():
   return 'NOT MADE YET!'
@app.route('/Report_Bug')
def Report_Bug():
   return 'NOT MADE YET!'
if __name__ == "__main__":
 app.run(debug=True)