const authMiddleware = (req, res, next) => {
  const pathname = req.path;
  if (req.isAuthenticated()) {
    if (pathname === "/auth/login" || pathname === "/auth/register") {
      return res.redirect("/");
    }
    next();
  } else {
    if (pathname === "/auth/login" || pathname === "/auth/register") {
      next();
    }
    else {
      return res.redirect('/v1/auth/login');
    }
  }
}

export { authMiddleware }