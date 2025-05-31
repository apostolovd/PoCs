// Setting up the core application & including express-fileupload (which has SSPP capabilities)
const express = require('express');
const fileUpload = require('express-fileupload');
const app = express();
const port = 8080

// Exposing fileUpload and its SSPP capabilities
app.use(fileUpload({
    parseNested: true
}));

// Selecting EJS lib
app.set('view engine', 'ejs');

// Setting up routes
app.get('/', (req, res) => {
    res.render('index');
});

// Starting the app
app.listen(port, () => {
    console.log(`We are now listening on port ${port}`)
})