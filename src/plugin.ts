export interface IRegister {
    (server:any, options:any, next:any): void;
    attributes?: any;
}

export default
class Auth {
    db:any;
    bcrypt:any;
    boom:any;
    joi:any;

    constructor(private mode:any, private ttl?:any) {
        this.register.attributes = {
            name: 'bemily-authentication',
            version: '0.1.0'
        };
        this.bcrypt = require('bcrypt');
        this.boom = require('boom');
        this.joi = require('joi');
    }

    register:IRegister = (server, options, next) => {
        server.bind(this);

        server.register(require('hapi-auth-cookie'), (err) => {
            if(err) {
                this.errorInit(err);
            }

            server.auth.strategy('session', 'cookie', this.mode, {
                password: 'secret',
                ttl: this.ttl || 600000,
                keepAlive: true,
                cookie: 'bemily_session',
                isSecure: false
            });

            server.dependency('bemily-database', (server, continueRegister) => {
                this.db = server.plugins['bemily-database'];
                continueRegister();
                next();
                this._register(server, options);
            });
        });
    };

    private _register(server, options) {

        server.route({
            method: 'GET',
            path: '/logout',
            handler: (request, reply) => {
                request.auth.session.clear();
                reply('logged out');
            }
        });

        server.route({
            method: 'POST',
            path: '/login',
            config: {
                auth: {
                    mode: 'try',
                    strategy: 'session'
                },
                handler: this.login,
                description: 'Perform login against backend.',
                tags: ['api', 'user', 'auth', 'authentication', 'cookies'],
                validate: {
                    payload: {
                        username: this.joi.string().alphanum().min(3).max(30).required()
                            .description('User id from "LDAP"'),
                        password: this.joi.string().alphanum().min(3).max(30).required()
                            .description('User password (same as rz-password)')
                    }
                }
            }
        });

    }

    login (request, reply) {
        if (request.auth.isAuthenticated) {
            return reply('already authenticated');
        }
        if(typeof request.payload === 'string') {
            request.payload = JSON.parse(request.payload)
        }

        if (!request.payload.username || !request.payload.password) {
            return reply(this.boom.badRequest('Missing username or password'));
        }
        else {
            this.db.getUserLogin(request.payload.username, (err, user) => {
                if (!user || !user.length) {
                    // TODO check LDAP
                    return reply(this.boom.unauthorized('NEEDS LDAP CHECK'));
                }
                if (request.payload.password === user[0].value.password) {
                    reply(user[0]);
                    request.auth.session.set(user[0]);
                } else {
                    reply(this.boom.unauthorized('Wrong username or password'));
                }

                //this.bcrypt.compare(password, user[0].value.password, function (err, isValid) {
                //    reply(err, isValid, user[0]);
                //});
            });

        }
    }

    errorInit(err) {
        if (err) {
            console.log('Error: Failed to load plugin:', err);
        }
    }
}