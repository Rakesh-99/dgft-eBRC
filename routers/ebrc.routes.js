import express from 'express';
import { fileEbrc, getToken, testEbrcWithSampleData } from '../controllers/ebrc.controller.js';
const ebrcRoutes = express.Router();




ebrcRoutes
    .get('/get-token', getToken)
    .post('/file', fileEbrc)
    .post('/test', testEbrcWithSampleData)



export default ebrcRoutes; 