import express from 'express';
import { fileEbrc, getToken, testEbrcWithSampleData } from '../controllers/ebrc.controller.js';
const ebrcRoutes = express.Router();




ebrcRoutes
    .post('/get-token', getToken)
    .post('/file', fileEbrc)
  



export default ebrcRoutes; 