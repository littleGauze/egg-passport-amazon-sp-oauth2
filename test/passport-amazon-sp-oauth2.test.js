'use strict';

const mock = require('egg-mock');

describe('test/passport-amazon-sp-oauth2.test.js', () => {
  let app;
  before(() => {
    app = mock.app({
      baseDir: 'apps/passport-amazon-sp-oauth2-test',
    });
    return app.ready();
  });

  after(() => app.close());
  afterEach(mock.restore);

  it('should GET /', () => {
    return app.httpRequest()
      .get('/')
      .expect('hi, passportAmazonSpOauth2')
      .expect(200);
  });
});
