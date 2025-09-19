import express from 'express';
import { 
    fileEbrc, 
    getToken, 
} from '../controllers/ebrc.controller.js';

const ebrcRoutes = express.Router();

// Main endpoints
ebrcRoutes.post('/get-token', getToken);
ebrcRoutes.post('/file', fileEbrc);


export default ebrcRoutes;