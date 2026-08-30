function apenasAdmin(req, res, next) {
    if (!req.usuario) {
        return res.status(401).json({
            erro: 'Usuário não autenticado'
        });
    }

    if (req.usuario.tipo !== 'admin') {
        return res.status(403).json({
            erro: 'Acesso permitido apenas para administradores'
        });
    }

    next();
}

module.exports = apenasAdmin;