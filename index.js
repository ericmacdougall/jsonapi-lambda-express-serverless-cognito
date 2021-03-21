const serverless = require('serverless-http');
const app = require('express')();
const API = require('json-api');
const APIError = API.types.Error;
const mongoose = require('mongoose');
mongoose.Promise = require('bluebird');
mongoose.set('debug', true)
const CognitoExpress = require('cognito-express');
const modelObj = require('serverless-models')(mongoose);
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const AWS = require('aws-sdk');
global.fetch = require('node-fetch');
const sendText = require('twilio-alerts').sms;
const generateNumberCode = require('./util/generateNumberCode.js');

const cognitoExpress = new CognitoExpress({
  region: process.env.AWS_REGION,
  cognitoUserPoolId: process.env.COGNITO_POOL_ID,
  tokenUse: 'access',
  tokenExpiration: process.env.COGNITO_EXPIRATION
});

// cached DB connection, defined in global scope for use anywhere..
let connection;

const authenticatedRoute = (req, res, next) => {
  let accessTokenFromClient = req.headers.accesstoken;
  if (!accessTokenFromClient)
    return res.status(401).send('Access Token missing from header');
  cognitoExpress.validate(accessTokenFromClient, (err, response) => {
    if (err) return res.status(401).send(err);
    res.locals.user = response;
    next();
  });
};

const registry = new API.ResourceTypeRegistry(modelObj.resources, {
  dbAdapter: new API.dbAdapters.Mongoose(modelObj.models)
});

const Controller = new API.controllers.API(registry);

const Docs = new API.controllers.Documentation(registry, {
  name: 'Serverless API'
});
const Front = new API.httpStrategies.Express(Controller, Docs);

var SrvModel = process.env.MODEL;
var SrvRoute = process.env.route;

const poolData = {
  UserPoolId: process.env.COGNITO_POOL_ID,
  ClientId: process.env.COGNITO_CLIENT_ID
};

const cognitoIdentityServiceProvider = new AWS.CognitoIdentityServiceProvider();

const pool_region = process.env.AWS_DEFAULT_REGION;
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);

const approvedPhoneNumbers = {};

app
  .route('/:type(' + SrvRoute + ')')
  .get(authenticatedRoute, Front.customAPIRequest({
    queryFactory: async opts => {
      return await opts.makeQuery(opts)
    },
    resultFactory: async (opts, qf) => {
      try {
        const query = await qf(opts);
        const results = await opts
          .runQuery(query)
          .then(query.returning, query.catch);
        results.document.primary._data.value.data.forEach((element) => {
          if (element._attrs.owner_id != opts.serverRes.locals.user.sub) {
			//Hide attributes that are private if listing a user record and not the owner
            delete element._attrs.geoLat;
            delete element._attrs.geoLong;

          }
        })
        return results;
      } catch (err) {
        console.log('Error running query: ', err);
      }
    }
  }))
  .post(
    Front.customAPIRequest({
      queryFactory: async opts => {
        const userReq = JSON.parse(opts.serverReq.body.toString());
        console.log(typeof userReq.data);
        if (userReq.data && typeof userReq.data === 'object') {
          const user = userReq.data.attributes;
          if (user.email && user.password) {
            const cleanedUserName = user.userName.replace(
              /[^a-zA-Z0-9_-]/g,
              ''
            );
            const cleanedPhoneNumber = '+' + user.accountPhone;
            if (cleanedUserName != user.userName) {
              throw new APIError({
                title:
                  'Username contains invalid characters. Username can only contain letters, numbers, hyphens, and underscores.',
                status: 400
              });
            };
            user.email = user.email.toLowerCase();
            const matchingUsernames = await modelObj.models.User.find({ userName: user.userName });
            const matchingPhones = await modelObj.models.User.find({ accountPhone: user.accountPhone });
            console.log("User name check result: ", matchingUsernames)
            if (matchingUsernames.length) {
              throw new APIError({
                title:
                  'Username already in use.',
                status: 400
              });
            }
            if (matchingPhones.length) {
              throw new APIError({
                title:
                  'Phone number already in use.',
                status: 400
              });
            }
            let attributeList = [];
            attributeList.push(
              new AmazonCognitoIdentity.CognitoUserAttribute({
                Name: 'name',
                Value: user.userName || ''
              })
            );
            attributeList.push(
              new AmazonCognitoIdentity.CognitoUserAttribute({
                Name: 'email',
                Value: user.email || ''
              })
            );
            attributeList.push(
              new AmazonCognitoIdentity.CognitoUserAttribute({
                Name: 'phone_number',
                Value: cleanedPhoneNumber || ''
              })
            );
            const cognitoUser = await new Promise(resolve => {
              userPool.signUp(
                user.email,
                user.password,
                attributeList,
                null,
                (err, result) => {
                  if (err) resolve(err);
                  else resolve(result);
                }
              );
            });
            if (cognitoUser && cognitoUser.userSub) {
              opts.serverRes.locals.user = {
                sub: cognitoUser.userSub
              };
              const origQuery = await opts.makeQuery(opts);
              origQuery.records.value.data[0]._attrs.userNameLowercase = origQuery.records.value.data[0]._attrs.userName.toLowerCase();
              cognitoIdentityServiceProvider.adminUpdateUserAttributes(
                {
                  UserAttributes: [
                    {
                      Name: 'phone_number_verified',
                      Value: 'true'
                    }
                  ],
                  UserPoolId: process.env.COGNITO_POOL_ID,
                  Username: user.email
                },
                (err, result) => {
                  if (err) {
                    console.log(err, err.stack);
                  } else {
                    console.log(result);
                  }
                }
              );

              return origQuery;
            } else {
              throw new APIError({
                title: cognitoUser.message,
                status: 400
              });
            }
          } else {
            throw new APIError({
              title: 'email and password is required.',
              status: 400
            });
          }
        } else {
          throw new APIError({
            title: 'This method is only allowed singular record.',
            status: 400
          });
        }
      },
      resultFactory: async (opts, qf) => {
        const query = await qf(opts);
        const results = await opts
          .runQuery(query)
          .then(query.returning, query.catch);
		  
		//Set a default 'role' in your local database/role manager
        var currentUser = results.document.primary._data.value.data[0];
        var userRole = await modelObj.models.role.findOne({ 'name': "User" });
        var userRoleUpdate = await modelObj.models.User.updateOne({ '_id': currentUser.id }, { $push: { role: userRole._id } })

		//Handle affiliate/referrals by username 
        if (currentUser._attrs.referrerUsername) {
          var referrer = await modelObj.models.User.findOne({'userNameLowercase': currentUser._attrs.referrerUsername});
          var userReferrerUpdate = await modelObj.models.User.updateOne({ '_id': currentUser.id }, { $push: { referrer: referrer._id } });
        }
        return results;
      }
    })
  )
  .patch(
    authenticatedRoute,
    Front.customAPIRequest({
      queryFactory: async opts => {
        const origQuery = await opts.makeQuery(opts);
        const ids = origQuery.query.patch.value.data.map(a => a.id);
        const modelsName = await modelObj.models[SrvModel].find({
          _id: { $in: ids }
        });
        if (
          modelsName.filter(
            model =>
              model.owner_id ===
              origQuery.query.patch.value.data[0]._attrs.owner_id
          ).length !== ids.length
        ) {
          throw new APIError({
            status: 401,
            title: 'Unauthenticated'
          });
        } else {
          if (origQuery.query.patch.value.data[0]._attrs.accountPhone) {
            var existingPhoneNumbers = await modelObj.models.User.find({ accountPhone: origQuery.query.patch.value.data[0]._attrs.accountPhone });
            if (existingPhoneNumbers.length) {
              throw new APIError({
                title:
                  'Phone number already in use.',
                status: 400
              });
            }
          }
          if (origQuery.query.patch.value.data[0]._attrs.email) {
            var existingEmails = await modelObj.models.User.find({ email: origQuery.query.patch.value.data[0]._attrs.email });
            if (existingEmails.length) {
              throw new APIError({
                title:
                  'Email address already in use.',
                status: 400
              });
            }
          }
          return origQuery;
        }
      }
    })
  );

app.post('/' + SrvRoute + '/changepassword', (req, res) => {
  const userReq = JSON.parse(req.body.toString());
  cognitoUser = new AmazonCognitoIdentity.CognitoUser({
    Username: userReq.email,
    Pool: userPool
  });
  cognitoUser.forgotPassword({
    onSuccess: function (result) {
      return res.status(200).send({
        status: 200,
        title: 'Verification code sent',
        ...result
      });
    },
    onFailure: function (err) {
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: err.message
          }
        ]
      });
    }
  });
});



app.post('/' + SrvRoute + '/confirmpassword', (req, res) => {
  const userReq = JSON.parse(req.body.toString());
  cognitoUser = new AmazonCognitoIdentity.CognitoUser({
    Username: userReq.email,
    Pool: userPool
  });
  cognitoUser.confirmPassword(userReq.otp, userReq.newPassword, {
    onSuccess: function (result) {
      return res.status(200).send({
        status: 200,
        title: 'Password changed',
        ...result
      });
    },
    onFailure: function (err) {
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: err.message
          }
        ]
      });
    }
  });
});

app.post('/' + SrvRoute + '/login', async (req, res) => {
  const userReq = JSON.parse(req.body.toString());
  if (userReq.email && userReq.password) {
    const payload = {
      UserPoolId: process.env.COGNITO_POOL_ID,
      AuthFlow: 'ADMIN_NO_SRP_AUTH',
      ClientId: process.env.COGNITO_CLIENT_ID,
      AuthParameters: {
        USERNAME: userReq.email,
        PASSWORD: userReq.password
      }
    };
    cognitoIdentityServiceProvider.adminInitiateAuth(payload, async (err, data) => {
      if (err) {
        res.status(400).send({
          errors: [
            {
              status: 400,
              title: err.message
            }
          ]
        });
      } else {
        var userObject = await modelObj.models.User.findOne({ 'email': userReq.email });
		//Include the user's permissions in the login response
        if (userObject.role.length) {
          var role = await modelObj.models.role.findOne({ '_id': userObject.role[0] });
          var permissions = await modelObj.models.rolepermission.find({ '_id': { $in: role.rolePermissions } });
          var permissionsList = permissions.map(x => x.name);
        } else {
          var permissionsList = [];
        }

        res.status(200).send({
          status: 200,
          title: 'Login successful',
          email: userReq.email,
          userId: userObject._id,
          username: userObject.userName,
          scoreboardRolePermissions: permissionsList,
          ...data
        });
      }
    });
  } else {
    return res.status(400).send({
      errors: [
        {
          status: 400,
          title: 'email and password is required'
        }
      ]
    });
  }
});

app.post('/' + SrvRoute + '/refresh', (req, res) => {
  console.log('RECEIVED TOKEN REFRESH');
  const userReq = JSON.parse(req.body.toString());
  console.log('INCOMING DATA: ', userReq);
  const RefreshToken = new AmazonCognitoIdentity.CognitoRefreshToken({
    RefreshToken: userReq.refreshToken
  });
  const userData = {
    Username: userReq.email,
    Pool: userPool
  };

  const cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
  console.log('COGNITO USER: ', cognitoUser);

  cognitoUser.refreshSession(RefreshToken, (err, session) => {
    if (err) {
      console.log('REFRESH ERR: ', err);
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: err.message
          }
        ]
      });
    } else {
      let retObj = {
        access_token: session.accessToken.jwtToken,
        id_token: session.idToken.jwtToken,
        refresh_token: session.refreshToken.token
      };
      console.log('Good refresh');
      return res.json(retObj);
    }
  });
});

app.post('/' + SrvRoute + '/logout', (req, res) => {
  const params = {
    AccessToken: req.headers.accesstoken
  };
  cognitoIdentityServiceProvider.globalSignOut(params, (err, data) => {
    if (err) {
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: err.message
          }
        ]
      });
    } else {
      return res.status(200).send({
        status: 200,
        title: 'Sign out successful'
      });
    }
  });
});

app.post('/' + SrvRoute + '/confirm', (req, res) => {
  const userReq = JSON.parse(req.body.toString());
  if (userReq.email && userReq.otp) {
    const userData = {
      Username: userReq.email,
      Pool: userPool
    };

    let cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.confirmRegistration(userReq.otp, true, (err, result) => {
      if (err) {
        return res.status(400).send({
          errors: [
            {
              status: 400,
              title: err.message
            }
          ]
        });
      } else {
        return res.status(200).send({
          status: 200,
          title: 'User confirmed.'
        });
      }
    });
  } else {
    return res.status(400).send({
      errors: [
        {
          status: 400,
          title: 'email and otp is required'
        }
      ]
    });
  }
});

app.post('/' + SrvRoute + '/disable', (req, res) => {
  const userReq = JSON.parse(req.body.toString());
  const params = {
    AccessToken: req.headers.accesstoken
  };
  cognitoIdentityServiceProvider.getUser(params, (err, data) => {
    if (err) {
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: err.message
          }
        ]
      });
    } else {
      modelObj.models.User.updateOne(
        { email: userReq.email },
        { active: false },
        (err, result) => {
          if (err) {
            console.log(err);
          } else {
            console.log(result);
            return res.status(200).send({
              status: 200,
              title: 'User disabled',
              ...data
            });
          }
        }
      );
    }
  });
});

app.post('/' + SrvRoute + '/enable', (req, res) => {
  const userReq = JSON.parse(req.body.toString());
  if (userReq.email) {
    modelObj.models.User.updateOne(
      { email: userReq.email },
      { active: true },
      (err, result) => {
        if (err) {
          console.log(err);
        } else {
          console.log(result);
          return res.status(200).send({
            status: 200,
            title: 'User enabled.'
          });
        }
      }
    );
  } else {
    return res.status(400).send({
      errors: [
        {
          status: 400,
          title: 'email is required'
        }
      ]
    });
  }
});

app.post('/' + SrvRoute + '/resendcode', (req, res) => {
  const userReq = JSON.parse(req.body.toString());
  if (userReq.email) {
    const params = {
      Username: userReq.email,
      ClientId: process.env.COGNITO_CLIENT_ID
    };
    cognitoIdentityServiceProvider.resendConfirmationCode(
      params,
      (err, result) => {
        if (err) {
          console.log(err);
        } else {
          console.log(result);
          return res.status(200).send({
            status: 200,
            title: 'Confirmation code re-sent.'
          });
        }
      }
    );
  } else {
    return res.status(400).send({
      errors: [
        {
          status: 400,
          title: 'email is required'
        }
      ]
    });
  }
});

const storedCodes = {};
const pendingPhoneNumbers = {};
app.post('/' + SrvRoute + '/verifyPhone', async (req, res) => {
  try {
    const userReq = JSON.parse(req.body.toString());

    if (!userReq.phoneNumber) {
      return res
        .status(400)
        .json({ message: "Request is missing 'phoneNumber' key." });
    }
    let code = generateNumberCode(6);

    while (storedCodes[code]) {
      code = generateNumberCode(6);
    }

    storedCodes[code] = true;
    pendingPhoneNumbers[userReq.phoneNumber] = code;

    setTimeout(() => {
      delete storedCodes[code];
      delete pendingPhoneNumbers[userReq.phoneNumber];
    }, 300000);
    const cleanedPhoneNumber = '+' + userReq.phoneNumber;
    await sendText(cleanedPhoneNumber, `${code} is your verification code!`);

    return res.sendStatus(200);
  } catch (err) {
    console.log('ERR verifying phone: ', err);
    return res
      .status(500)
      .json({ message: 'There was an error processing your request.' });
  }
});

app.post('/' + SrvRoute + '/confirmPhoneCode', async (req, res) => {
  try {
    const userReq = JSON.parse(req.body.toString());

    if (!userReq.hasOwnProperty('code')) {
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: 'code is required'
          }
        ]
      });
    }

    if (!userReq.phoneNumber) {
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: 'phoneNumber is required'
          }
        ]
      });
    }

    if (
      !pendingPhoneNumbers[userReq.phoneNumber] ||
      pendingPhoneNumbers[userReq.phoneNumber].toString() !==
      userReq.code.toString()
    ) {
      return res.status(400).send({
        errors: [
          {
            status: 400,
            title: 'Invalid code'
          }
        ]
      });
    }

    delete storedCodes[userReq.code];
    delete pendingPhoneNumbers;
    [userReq.phoneNumber];
    approvedPhoneNumbers[userReq.phoneNumber] = true;
    return res.status(200).json({ message: 'Confirmed.' });
  } catch (err) {
    console.log('ERR confirming phone code: ', err);
    return res
      .status(500)
      .json({ message: 'There was an error processing your request.' });
  }
});

app.get('/' + SrvRoute + '/testlookup', (req, res) => {
  modelObj.models.Userconnection.aggregate(
    [
      {
        $lookup: {
          from: 'posts',
          localField: 'connectionName',
          foreignField: 'userName',
          as: 'posts'
        }
      }
    ],
    (err, data) => {
      if (err) {
        res.send(err.message);
      } else {
        res.send(data);
      }
    }
  );
});



app
  .route('/:type(' + SrvRoute + ')/:id')
  .get(authenticatedRoute, Front.apiRequest)
  .delete(
    authenticatedRoute,
    Front.customAPIRequest({
      queryFactory: async opts => {
        const origQuery = await opts.makeQuery(opts);
        const modelname = await modelObj.models[SrvModel].findById(
          opts.serverReq.params.id
        );
        if (modelname.owner_id === opts.serverRes.locals.user.sub)
          return origQuery;
        else {
          throw new APIError({
            status: 401,
            title: 'Unauthenticated'
          });
        }
      }
    })
  )
  .patch(
    authenticatedRoute,
    Front.customAPIRequest({
      queryFactory: async opts => {
        const origQuery = await opts.makeQuery(opts);
        const modelname = await modelObj.models[SrvModel].findById(
          opts.serverReq.params.id
        );
        if (modelname.owner_id === opts.serverRes.locals.user.sub)
          return origQuery;
        else {
          throw new APIError({
            status: 401,
            title: 'Unauthenticated'
          });
        }
      }
    })
  );

app
  .route('/:type(' + SrvRoute + ')/:id/relationships/:relationship')
  .get(authenticatedRoute, Front.apiRequest)
  .patch(
    authenticatedRoute,
    Front.customAPIRequest({
      queryFactory: async opts => {
        const origQuery = await opts.makeQuery(opts);
        const model = await modelObj.models[SrvModel].findById(
          opts.serverReq.params.id
        );
        if (model.owner_id === opts.serverRes.locals.user.sub) return origQuery;
        else
          return res.status(401).send({
            errors: [
              {
                title: "You don't have permission to this operation.",
                status: 401
              }
            ]
          });
      }
    })
  );

app.use((req, res, next) =>
  Front.sendError(new APIError(404, undefined, 'Not Found'), req, res)
);

let handler = serverless(app);

module.exports.server = async (event, context) => {
  // The following line is critical for performance reasons to allow re-use of database connections across
  // calls to this Lambda function and avoid closing the database connection.
  context.callbackWaitsForEmptyEventLoop = false;

  try {
    if (connection === undefined) {
      connection = await mongoHandler();
    }

    const result = await handler(event, context);
    return result;
  } catch (err) {
    console.error('Mongo/Serverless error: ', err);
  }
};

async function mongoHandler() {
  switch (mongoose.connection.readyState) {
    /* 
        readyState can be:
        0 - disconnected
        1 - connected
        2 - connecting
        3 - disconnecting
      */
    case 0:
      // No connection exists, create a new one
      console.log('Connecting to Mongo');
      return mongoose.connect(process.env.MONGO_URL, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        useFindAndModify: false,
        // Turning off buffering so queries will fail immediately instead of pending
        bufferCommands: false,
        bufferMaxEntries: 0
      });
    case 1:
    case 2:
      // Either already connecting or connected.  Since 'connection' should persist,
      // I don't expect this code to ever run.  But it's better to have
      // redundancies than assumptions.
      console.log('Reassigning connection');
      return mongoose.connection;
    case 3:
      // If Mongo is still disconnecting, wait 100ms and try again
      console.log('Mongoose disconnecting, waiting');
      return new Promise(resolve =>
        setTimeout(() => resolve(mongoHandler()), 100)
      );
  }

  // If somehow nothing else triggers, just return connection
  return connection;
}
