import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
const app = express();
import ebrcRoutes from './routers/ebrc.routes.js';
const port = process.env.PORT || 8050;
import errorHandlerMIddleware from './middlewares/errorHandlerMiddleware.js';



app.use(express.json());
app.use('/api/v1', ebrcRoutes);
app.use(errorHandlerMIddleware);



app.listen(port, '0.0.0.0', () => {
    console.log(`App is listening at port : ${port}`);
})


