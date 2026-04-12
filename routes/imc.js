const express = require('express');
const router = express.Router();

router.post('/calcular', (req, res) => {
    const { peso, altura } = req.body;
    const p = parseFloat(peso);
    const a = parseFloat(altura);

    if (!p || !a) return res.redirect('/');

    const imc = (p / (a * a)).toFixed(2);
    let estado = "";
    let color = "";

    if (imc < 18.5) { estado = "BAJO PESO"; color = "#FFC107"; }
    else if (imc <= 24.9) { estado = "PESO NORMAL"; color = "#28A745"; }
    else if (imc <= 29.9) { estado = "SOBREPESO"; color = "#FD7E14"; }
    else { estado = "OBESIDAD"; color = "#DC3545"; }

    res.render('index', { res_imc: imc, res_estado: estado, res_color: color });
});

module.exports = router;