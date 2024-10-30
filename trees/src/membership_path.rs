#[derive(Clone, Debug, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct MembershipPath<F> {
    path: Vec<F>,
}

impl<F> MembershipPath<F> {
    pub fn new() -> Self {
        MembershipPath { path: vec![] }
    }

    pub fn append(&mut self, el: F) {
        self.path.push(el)
    }

    pub fn as_vec(self) -> Vec<F> {
        self.path
    }

    pub fn path_len(&self) -> usize {
        self.path.len()
    }

    pub fn from_array<const N: usize, const L: usize>(
        array: [[F; N]; L],
    ) -> Vec<MembershipPath<F>> {
        array
            .into_iter()
            .map(|path| {
                let mut mp = MembershipPath::new();
                path.into_iter().for_each(|el| mp.append(el));
                mp
            })
            .collect()
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
        let path: MembershipPath<i32> = MembershipPath::new();
        assert_eq!(path.path.len(), 0);
    }

    #[test]
    fn test_append() {
        let mut path: MembershipPath<i32> = MembershipPath::new();
        path.append(2);
        path.append(3);

        assert_eq!(path.path.len(), 2);
        assert_eq!(path.path[0], 2);
        assert_eq!(path.path[1], 3);
    }

    #[test]
    fn test_into_iter() {
        let mut path: MembershipPath<i32> = MembershipPath::new();
        path.append(2);
        path.append(3);

        let mut iter = path.into_iter();
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_iter() {
        let mut path: MembershipPath<i32> = MembershipPath::new();
        path.append(1i32);
        let path_ref = &path;

        let mut iter = path_ref.into_iter();
        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_clone() {
        let mut path: MembershipPath<i32> = MembershipPath::new();
        path.append(1);
        let cloned_path = path.clone();

        assert_eq!(cloned_path.path.len(), 1);
        assert_eq!(cloned_path.path[0], 1);
    }

    #[test]
    fn test_from_array() {
        let array: [[i32; 3]; 2] = [[1, 2, 3], [4, 5, 6]];

        let paths = MembershipPath::from_array(array);

        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].clone().as_vec(), vec![1, 2, 3]);
        assert_eq!(paths[1].clone().as_vec(), vec![4, 5, 6]);
    }
}
