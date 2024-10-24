#[derive(Clone, Debug, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct MembershipPath<F> {
    path: Vec<F>,
}

impl<F> MembershipPath<F> {
    pub fn new(el: F) -> Self {
        MembershipPath { path: vec![el] }
    }

    pub fn append(&mut self, el: F) {
        self.path.push(el)
    }

    pub fn as_vec(self) -> Vec<F> {
        self.path
    }
}

impl<F> IntoIterator for MembershipPath<F> {
    type Item = F;
    type IntoIter = std::vec::IntoIter<F>;

    fn into_iter(self) -> Self::IntoIter {
        self.path.into_iter()
    }
}

impl<'a, F> IntoIterator for &'a MembershipPath<F> {
    type Item = &'a F;
    type IntoIter = std::slice::Iter<'a, F>;

    fn into_iter(self) -> Self::IntoIter {
        self.path.iter()
    }
}

impl<F, const N: usize> TryInto<[F; N]> for MembershipPath<F>
where
    F: Copy,
{
    type Error = &'static str;

    fn try_into(self) -> Result<[F; N], Self::Error> {
        let vec_len = self.path.len();
        if vec_len != N {
            return Err("Cannot convert to array: length mismatch");
        }

        // Convert Vec<F> to array [F; N]
        let array: [F; N] = self.path.try_into().map_err(|_| "Conversion failed")?;
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let path: MembershipPath<i32> = MembershipPath::new(1);
        assert_eq!(path.path.len(), 1);
        assert_eq!(path.path[0], 1);
    }

    #[test]
    fn test_append() {
        let mut path: MembershipPath<i32> = MembershipPath::new(1);
        path.append(2);
        path.append(3);

        assert_eq!(path.path.len(), 3);
        assert_eq!(path.path[1], 2);
        assert_eq!(path.path[2], 3);
    }

    #[test]
    fn test_into_iter() {
        let mut path: MembershipPath<i32> = MembershipPath::new(1);
        path.append(2);
        path.append(3);

        let mut iter = path.into_iter();
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_iter() {
        let path: MembershipPath<i32> = MembershipPath::new(1);
        let path_ref = &path;

        let mut iter = path_ref.into_iter();
        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_clone() {
        let path: MembershipPath<i32> = MembershipPath::new(1);
        let cloned_path = path.clone();

        assert_eq!(cloned_path.path.len(), 1);
        assert_eq!(cloned_path.path[0], 1);
    }
}
