const express = require('express');
var path = require('path');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
const cors = require('cors');
const crypto = require('crypto');
const colors = require('colors');
var MyInfoConnector = require('myinfo-connector-nodejs');

var CryptoJS = require("crypto-js");
var jose = require('node-jose');
const jwt  = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const port = 3001;
const config = require('./config/config.js');


app.use(express.json());
app.use(cors());


app.set('views', path.join(__dirname, 'public/views'));
app.set('view engine', 'pug');

app.use(express.static('public'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: false
}));
app.use(cookieParser());

app.get('/', function (req, res) {
  res.sendFile(__dirname + '/public/index.html');
});

// get the environment variables (app info) from the config
app.get('/getEnv', function (req, res) {

  try {
    var environment = process.argv[2].toUpperCase(); // get from package.json process argument
    // console.log("Environment:".yellow, environment);
    if (environment == "SANDBOX") {
      // overwrite the Environment, Token URL and Person URL if Environemnt is 'Sandbox'. 
      // 'Sandbox' environment doesn't have Payload Encryption & PKI Digital Signature
      config.MYINFO_CONNECTOR_CONFIG.ENVIRONMENT = environment;
      config.MYINFO_CONNECTOR_CONFIG.TOKEN_URL = config.APP_CONFIG.MYINFO_API_TOKEN[environment];
      config.MYINFO_CONNECTOR_CONFIG.PERSON_URL = config.APP_CONFIG.MYINFO_API_PERSON[environment];
      console.log("Payload Encryption & PKI Digital Signature:".yellow, "Disabled".grey,"(Sandbox Env)");
    } else {
      console.log("Payload Encryption & PKI Digital Signature:".yellow, "Enabled".green,"(Test Env)");
    }

    if (config.APP_CONFIG.DEMO_APP_CLIENT_ID == undefined || config.APP_CONFIG.DEMO_APP_CLIENT_ID == null) {
      res.status(500).send({
        "error": "Missing Client ID"
      });
    } else {
      res.status(200).send({
        "clientId": config.APP_CONFIG.DEMO_APP_CLIENT_ID,
        "redirectUrl": config.APP_CONFIG.DEMO_APP_CALLBACK_URL,
        "attributes": config.APP_CONFIG.DEMO_APP_SCOPES,
        "purpose": config.APP_CONFIG.DEMO_APP_PURPOSE,
        "environment": environment,
        "authApiUrl": config.APP_CONFIG.MYINFO_API_AUTHORISE[environment],
      });
    }
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      "error": error
    });
  }
});


// callback function - directs back to home page
//app.get('/callback', function (req, res) {
//  res.sendFile(__dirname + '/public/index.html');
//});


// getPersonData function - call MyInfo Token + Person API
app.post('/getPersonData', function (req, res, next) {

  try {
    // get variables from frontend
    var authCode = req.body.authCode;
    var state = req.body.state;
    var txnNo = crypto.randomBytes(10).toString("hex");

    // console.log("> AuthCode   : ", authCode);
    // console.log("> State      : ", state);
    // console.log("> txnNo      : ", txnNo);

    let connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG);
    console.log("Calling MyInfo NodeJs Library...".green);

    connector.getMyInfoPersonData(authCode, state, txnNo)
      .then(personData => {
        
        /* 
        P/s: Your logic to handle the person data ...
        */

        console.log('--- Sending Person Data From Your-Server (Backend) to Your-Client (Frontend)---:'.green);
        console.log(JSON.stringify(personData)); // log the data for demonstration purpose only
        res.status(200).send(personData); //return personData
      })
      .catch(error => {
        console.log("---MyInfo NodeJs Library Error---".red);
        console.log(error);
        res.status(500).send({
          "error": error
        });
      });
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      "error": error
    });
  }
});

function base64url(source) {
    // Encode in classical base64
    encodedSource = CryptoJS.enc.Base64.stringify(source)
    // Remove padding equal characters
    encodedSource = encodedSource.replace(/=+$/, '')
    // Replace characters according to base64url specifications
    encodedSource = encodedSource.replace(/\+/g, '-')
    encodedSource = encodedSource.replace(/\//g, '_')
    
    return encodedSource
}

// getPersonData function - call MyInfo Token + Person API
//
function getIdToken(personData) {


   console.log("ID-TOKEN");


   var currentTimestamp = Math.floor(Date.now() / 1000) // Prepare timestamp in seconds
   var uinfin = personData.uinfin.value || "undefined";
   var name = personData.name.value || "undefined";
   var nationality = personData.nationality.desc || "undefined";
   var race = personData.race.desc || "undefined";

   // Set headers for JWT
   var header = {
	'alg': 'RS256',
	'format': "compact"
   };


    var data = {
        "sub": "s=S8829314B,u=1c0cee38-3a8f-4f8a-83bc-7a0e4c59d6a9",
        "aud": "hHtZFboK83G3X7efaD6hFd5JbgLOSl2d", 			//client_id
    	"amr": ["PWD","SWK"],
        "uinfin": uinfin,
        "name": name,
        "nationality": nationality,
        "race": race,
        "iss": "https://stg-id.singpass.gov.sg",
	'nonce': '1651440523' || '',
	'nbf': currentTimestamp,
	'auth_time': currentTimestamp,
	'exp': currentTimestamp + 3000000, // expiry time is 3000 seconds from time of creation
	'iat': currentTimestamp,
	'jti': Math.random().toString(36).slice(2)
    };


   // encode header and data
   var stringifiedHeader = CryptoJS.enc.Utf8.parse(JSON.stringify(header))
   var encodedHeader = base64url(stringifiedHeader)

   var stringifiedData = CryptoJS.enc.Utf8.parse(JSON.stringify(data).replace(/\\\\/g, '\\'))
   var encodedData = base64url(stringifiedData)


   // build token
   //
   var token = `${encodedHeader}.${encodedData}`


   var signOptions = {
      algorithm: "RS256"
   }


   const privateKey = fs.readFileSync("./cert/your-sample-app-private-cert.pem", "utf8");

   var signed_token = jwt.sign(data, privateKey, signOptions);

   return (signed_token);

}


app.post('/oauth2/token', function (req, res, next) {

console.log("TOKEN");
  try {
    // get variables from frontend
    var authCode = req.body.code;
    var state = req.body.state;
    var txnNo = crypto.randomBytes(10).toString("hex");

    console.log("> AuthCode   : ", authCode);
    console.log("> State      : ", state);
    console.log("> txnNo      : ", txnNo);

    let connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG);
    console.log("Calling MyInfo NodeJs Library...".green);

    connector.getMyInfoPersonData(authCode, state, txnNo)
      .then(personData => {
        
        /* 
        P/s: Your logic to handle the person data ...
        */

        var idToken = getIdToken(personData);
        var resp = {
           "access_token" : idToken,
           "token_type" : "Bearer",
           "id_token" : idToken
        }

        console.log('--- Sending id_token Data From Your-Server (Backend) to Your-Client (Frontend)---:'.green);
        console.log(JSON.stringify(resp)); // log the data for demonstration purpose only
        res.status(200).send(resp); //return personData
      })
      .catch(error => {
        console.log("---MyInfo NodeJs Library Error---".red);
        console.log(error);
        res.status(500).send({
          "error": error
        });
      });
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      "error": error
    });
  }
});


function signJWT(jwt) {


   var signedJWT;
   const privateKeyPEM = fs.readFileSync("./cert/your-sample-app-private-cert.pem", { encoding: "utf8" });

   // parsing the PEM formatted private Key 
   jose.JWK.asKey(privateKeyPEM, "pem").then(function(jwk) {
	
	// jwk contains the parsed key 

	// creating the signature, using RS256 algorithm 
	var signature = 
		jose.JWS.createSign({
				alg: "RS256",
				format: 'compact'
			}, jwk).
				update(JSON.stringify(jwt), "utf8").
					final();
	
	// signing 
	signature.then(function(result) {

	   // result contains a signed ID Token, ready to send to the Authentication Service !
	   signedJWT = result;
	   
	}, function(error) {
		console.log(error);
	});
   });
   return (signedJWT);
}

app.get('/oauth2/authorize', function (req, res) {

console.log("AUTHORIZE");
  var state = req.query.state
  var environment = process.argv[2].toUpperCase(); // get from package.json process argument

  var authoriseUrl = config.APP_CONFIG.MYINFO_API_AUTHORISE[environment] + "?client_id=" + config.APP_CONFIG.DEMO_APP_CLIENT_ID +
        "&attributes=" + config.APP_CONFIG.DEMO_APP_SCOPES +
        "&purpose=" + config.APP_CONFIG.DEMO_APP_PURPOSE +
        "&state=" + encodeURIComponent(state) +
        "&redirect_uri=" + config.APP_CONFIG.DEMO_APP_CALLBACK_URL;

  res.redirect(authoriseUrl);
});


app.post('/oauth3/token', function (req, res) {
  console.log("GET TOKEN");
  console.log(req.body);
  console.log(req.headers);

  try {
    // get variables from frontend
    var authCode = req.body.code;
    var state = req.body.state;

    console.log("> AuthCode   : ", authCode);
    console.log("> State      : ", state);


    let connector = new MyInfoConnector(config.MYINFO_CONNECTOR_CONFIG);
    console.log("Calling MyInfo NodeJs Library...".green);

    connector.getAccessToken(authCode, state)
      .then(accessToken => {
        
        /* 
        P/s: Your logic to handle the access Token...
        */

        var resp = { "id_token": "eyJ4NXQjUzI1NiI6Ik1yeE5SdE40UlcwZVpQVUZYemhwN3kwcmlibXpZbi05YzNQSHpKaXBlaWsiLCJ4NXQiOiIzemZJZVZNdmFMMkJ2U3J6VFFYaHY3dGdYOWMiLCJraWQiOiJTaWduaW5nS2V5IiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI5ZWYyZmI4NS0yNzYzLTQwY2MtOGZjZi1kNzExMGYyYTk3ZDUiLCJpZHBfbmFtZSI6Ik9wdHVzLUNBLURpcmVjdG9yeSIsInVzZXJfZG4iOiJjbj1uYnJ1Y2Usb3U9RW1wbG95ZWVzLG89ZGVtb2NvcnAsYz11cyIsImFtciI6WyJPVFAiLCJQV0QiXSwidXNlcl9sb2dpbmlkIjoibmJydWNlIiwiaXNzIjoiaHR0cHM6XC9cL3NzcC5vcGVuc2hpZnQuY2x1c3RlcnMuYWgtZGVtby5jb21cL2RlZmF1bHRcLyIsInVzZXJfZ3VpZCI6IjllZjJmYjg1LTI3NjMtNDBjYy04ZmNmLWQ3MTEwZjJhOTdkNSIsImFhbCI6IkFBTDEiLCJ0aWQiOiJlZmEwYTRiNi1kYmQ2LTRhOGYtYmQyYy0yYWRlMzc1NDI1ZmEiLCJzaWQiOiIwOGZkODc3OC1hYWE3LTRhOWMtODVhOS0yNmFjMzRjODJmNmQiLCJhY3IiOiJ1cm46aWFtOmFjcjphYWwxIiwiYXpwIjoiZjkxYmU2YzYtMDE1Mi00MjQ3LTlmNWEtMjNkMzJmNmU3MWVjIiwiYXV0aF90aW1lIjoxNjY1Njk2OTYyLCJleHAiOjE2NjU3MTg1NjIsImlhdCI6MTY2NTY5Njk2MiwiY2xpZW50X25hbWUiOiJBTlotSW5zdG8iLCJqdGkiOiJmNDA2ZTY3Ny01YjI5LTRhMGQtYjE5NC1iODdhZjQ5ZDYxNTAiLCJlbWFpbCI6InBhdWwuY29ubm9yQGJyb2FkY29tLmNvbSIsImNsaWVudF90bmFtZSI6ImRlZmF1bHQiLCJjbGllbnRfdGlkIjoiZWZhMGE0YjYtZGJkNi00YThmLWJkMmMtMmFkZTM3NTQyNWZhIiwidmVyIjoiMS4wIiwidXNlcl91bml2ZXJzYWxpZCI6Im5icnVjZSIsInRuYW1lIjoiZGVmYXVsdCIsInRva190eXBlIjoiSVQiLCJ1c2VyX3Jpc2tzY29yZSI6MTAwLCJhdWQiOlsiZjkxYmU2YzYtMDE1Mi00MjQ3LTlmNWEtMjNkMzJmNmU3MWVjIiwiaHR0cHM6XC9cL3NzcC5vcGVuc2hpZnQuY2x1c3RlcnMuYWgtZGVtby5jb21cL2RlZmF1bHRcLyJdLCJuYmYiOjE2NjU2OTY5NjIsInVzZXJfemZwIjpmYWxzZSwiY2xpZW50X3RyYW5zYWN0aW9uaWQiOiJzc3A6NWNlNTVkMzctZGYzNi00YmNhLWJjOGYtYzkxZTE2NDI0YmZhIiwidG9rX3NvdXJjZSI6IkZMUyJ9.QCKnbVBQ0zkwqqOGxPN131LoZ2HgKibXqhWUiNRrw72LrNkDHGZHX0Ryi2znczZH0gmI2GTyTobQVN6kLjWhyafCZIGzwvugvnIQVXMAeBpW9ak_POwyUX_W8w-jhzHW-fGqOAhjjcMGrLWLzO3UCDk4A-UuBMldSnsrzTFxQePtY_74euHPvy5hN5LdS4lxFIEjN-YMNzFvlYfalTdVsANVVAAudcWL2_UzoWPBoCAqm50t_4d_qvaXZdayU2IA2zTzl--nMmT9VfdSIC4Xua-I5t_4_0J7L7NxguEUL0nNvB2GdFtQQPn5Gzna_Jk4KKPybG7A9fWYXU3ADFp3bA", accessToken };

console.log("RESPONSE = ",resp);

        console.log('--- Sending Access Token From Your-Server (Backend) to Your-Client (Frontend)---:'.green);
        console.log(JSON.stringify(accessToken)); // log the data for demonstration purpose only
        res.setHeader('Content-Type', 'application/json');
        res.status(200).send(accessToken); //return accessToken
      })
      .catch(error => {
        console.log("---MyInfo NodeJs Library Error---".red);
        console.log(error);
        res.status(500).send({
          "error": error
        });
      });
  } catch (error) {
    console.log("Error".red, error);
    res.status(500).send({
      "error": error
    });
  }
});

app.get('/oauth2/userinfo', function (req, res) {
console.log("GET USERINFO");
  res.send("OK");
});


// callback function - directs back to home page
app.get('/callback', function (req, res) {
  console.log("CALLBACK QUERY : ",req.query);
  var ah_callbackUrl = "https://ssp.openshift.clusters.ah-demo.com/default/oauth2/v1/rp/callback" +"?code=" + req.query.code + "&state=" + req.query.state;
  res.redirect(ah_callbackUrl);
});




// catch 404 and forward to error handler
app.use(function (req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers
// print stacktrace on error
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: err
  });
});



app.listen(port, () => console.log(`Demo App Client listening on port ${port}!`));
