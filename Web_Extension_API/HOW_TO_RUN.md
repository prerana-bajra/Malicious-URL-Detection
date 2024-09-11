## Instructions to run the extension and API
The "Web_Extension_API" folder is a standalone project consisting of two main components: the API Flask server and the web extension.

### Step 1:
Cloning the "Web_Extension_API" folder and then creating an virtual environment.
Follow the commands :
```py
pip install virtualenv
```
```py
python3 -m venv env
```
For Windows : 
```py
env/Scripts/activate
```
For Mac : 
```py
source env/bin/activate
```
Installing the dependencies :
```py
pip install -r requirements.txt
```
### Step 2:
Running the flask API.
```py
python3 app.py
```
> [!CAUTION]
> Running the code might take some time.
Wait until the follwing message appears in the terminal:

<img width="923" alt="image" src="https://github.com/user-attachments/assets/39f64355-dbf2-4474-a748-087ebf61b6ae">

### Step 3:
Loading the extension in the browser. <br>
i. Go to browser extensions : <br>
for chrome :
```js
chrome://extensions/ 
```
for brave :
```js
brave://extensions/
```
ii. Click on "Load Unpacked"
<img width="958" alt="image" src="https://github.com/user-attachments/assets/574ae235-8418-411e-ba48-f1f94d7d06b6">

iii. Select the "Web_Extension_API" folder
<img width="958" alt="image" src="https://github.com/user-attachments/assets/8d437888-94c1-4b49-a0d8-bf7939d87148">

iv. The extension will appear here
<img width="959" alt="image" src="https://github.com/user-attachments/assets/aa8dad67-30bb-4684-8484-67c926d04293">

v. Click on the extension from quick access
<img width="959" alt="image" src="https://github.com/user-attachments/assets/8cc1356f-07d1-4171-83f7-bb62e7592b39">

vi. Paste any url and then click predict
<img width="959" alt="image" src="https://github.com/user-attachments/assets/e77207ce-0e0e-4825-b59d-8b4c8965e61d">







