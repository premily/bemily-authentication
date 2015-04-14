export interface IRegister {
    (server:any, options:any, next:any): void;
    attributes?: any;
}

export default
class Auth {
    db: any;
    bcrypt: any;
    constructor(private mode: any) {
        this.register.attributes = {
            name: 'bemily-authentication',
            version: '0.1.0'
        };
        this.bcrypt = require('bcrypt');
    }

    register:IRegister = (server, options, next) => {
        server.bind(this);
        this._register(server, options);
        server.register(require('hapi-auth-basic'), (err) => {

            server.auth.strategy('simple', 'basic', this.mode, {validateFunc: this.validate});

            server.dependency('bemily-database', (server, continueRegister) => {
                this.db = server.plugins['bemily-database'];
                continueRegister();
                next();
            });
        });
    };

    private _register(server, options) {
        server.route({
            method: 'POST',
            path: '/auth',
            handler: (request, reply) => {
                reply();
            }
        })

    }

    validate = (username, password, callback) => {

        this.db.getUserLogin(username, (err, user) => {
            if(!user || !user.length) {
                return callback(null, false);
            }

            if(password === user[0].value.password) {
                callback(err, true, user[0]);
            }

            //this.bcrypt.compare(password, user[0].value.password, function (err, isValid) {
            //    callback(err, isValid, user[0]);
            //});
        });

    };

    errorInit(error) {
        if (error) {
            console.log('Error: Failed to load plugin:', error);
        }
    }
}