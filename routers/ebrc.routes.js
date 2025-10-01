import express from 'express';
import {
    fileEbrc,
    getToken,
    generateCurlValues
} from '../controllers/ebrc.controller.js';

const ebrcRoutes = express.Router();

// Main endpoints
ebrcRoutes.post('/get-token', getToken);
ebrcRoutes.post('/file', fileEbrc);
ebrcRoutes.post('/curl-data', generateCurlValues)


export default ebrcRoutes;