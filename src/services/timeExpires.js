export const timeExpires = () => ({
  remember: new Date(new Date().setMonth(new Date().getMonth() + 2)),
  notRemember: new Date(new Date().setMonth(new Date().getMonth() + 1)),
});

export const cookieExpires = {
  rfTokenRemember: 2 * 31 * 24 * 60 * 60 * 1000,
  rfTokenNotRemember: 31 * 24 * 60 * 60 * 1000,
};
